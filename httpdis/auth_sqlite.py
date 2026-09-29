# -*- coding: utf-8 -*-
"""Opt-in SQLite authentication store; caller supplies path and lifecycle."""
import json
import math
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager

from six import string_types
from sonicprobe.libs import anysql
from sonicprobe.libs.urisup import uri_help_unsplit
from .auth_backend import STORE_TABLES
from .authentication import AuthenticationUnavailable

SCHEMA_VERSION = 1
APPLICATION_ID = 1213481301
MAX_RECORD_BYTES = 65536
MAX_KEY_LENGTH = 256
MAX_BUSY_TIMEOUT = 30
SCHEMA_SQL = '''CREATE TABLE auth_records (
    namespace TEXT NOT NULL,
    record_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (namespace, record_key)
)'''
EXPECTED_COLUMNS = (('namespace', 'TEXT', 1, None, 1),
                    ('record_key', 'TEXT', 1, None, 2),
                    ('payload', 'TEXT', 1, None, 0))


class SQLiteAuthStore(object):
    """Serialized transactions across threads/processes, JSON values, no pickle.

    The parent directory must already exist and be controlled by the daemon user.
    Connections belong to individual transactions and their calling thread.
    Database files are created mode 0600; insecure existing permissions are refused.
    Open one instance per process after forking, and close explicitly at shutdown.
    """
    def __init__(self, filename, timeout=5):
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or math.isnan(timeout) or math.isinf(timeout) or not 0 < timeout <= MAX_BUSY_TIMEOUT):
            raise ValueError('invalid SQLite authentication timeout')
        if hasattr(os, 'fspath'):
            filename = os.fspath(filename)
        if (not isinstance(filename, string_types) or not filename or filename == ':memory:'
                or filename.startswith('file:') or '\x00' in filename):
            raise ValueError('SQLite authentication requires an explicit local filename')
        self.filename = os.path.abspath(filename)
        self._lock = threading.RLock()
        self._owner = None
        self._pid = os.getpid()
        self._connection = None
        self._cursor = None
        self._closed = False
        self._identity = None
        self._uri = uri_help_unsplit(('sqlite3', None, self.filename,
                                     (('timeout_ms', str(timeout * 1000)),), None))
        try:
            with self.transaction():
                self._initialize()
        except (OSError, ValueError, TypeError, sqlite3.Error):
            self._closed = True
            raise AuthenticationUnavailable('cannot open private SQLite authentication store')

    def _connect(self):
        descriptor = None
        try:
            parent = os.stat(os.path.dirname(self.filename))
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022
                    or parent.st_uid != os.geteuid()):
                raise ValueError('authentication directory must be owned by the daemon and not group/world writable')
            if os.path.islink(self.filename):
                raise ValueError('authentication database cannot be a symlink')
            flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            if self._identity is None:
                flags |= os.O_CREAT
            descriptor = os.open(self.filename, flags, 0o600)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid != os.geteuid() or info.st_nlink != 1):
                raise ValueError('authentication database must be a private regular file owned by the daemon')
            identity = (info.st_dev, info.st_ino)
            if self._identity is not None and self._identity != identity:
                raise ValueError('authentication database was replaced')
            # Never fall back to legacy automatic reconnect, including on old Sonicprobe.
            self._connection = anysql.connect_by_uri(self._uri, auto_reconnect=False)
            self._cursor = self._connection.cursor()
            current = os.stat(self.filename)
            if identity != (current.st_dev, current.st_ino):
                raise ValueError('authentication database changed while opening')
            self._identity = identity
            self._query('PRAGMA synchronous=FULL')
            self._query('PRAGMA secure_delete=ON')
            mode = self._query('PRAGMA journal_mode=DELETE').fetchone(raw=True)[0]
            if mode.lower() != 'delete':
                raise ValueError('unsupported authentication journal mode')
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _query(self, sql, parameters=None):
        self._cursor.query(sql, parameters=parameters)
        return self._cursor

    def _initialize(self):
        version = self._query('PRAGMA user_version').fetchone(raw=True)[0]
        app_id = self._query('PRAGMA application_id').fetchone(raw=True)[0]
        tables = self._query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall(raw=True)
        if version == 0 and app_id == 0 and not tables:
            self._query(SCHEMA_SQL)
            self._query('PRAGMA application_id=%d' % APPLICATION_ID)
            self._query('PRAGMA user_version=%d' % SCHEMA_VERSION)
        elif version != SCHEMA_VERSION or app_id != APPLICATION_ID:
            raise ValueError('unsupported authentication database schema')
        columns = tuple(tuple(row[1:]) for row in self._query('PRAGMA table_info(auth_records)').fetchall(raw=True))
        if columns != EXPECTED_COLUMNS:
            raise ValueError('invalid authentication database schema')

    def _check_process(self):
        if self._pid != os.getpid() or self._closed:
            raise AuthenticationUnavailable('authentication store is closed or inherited across fork')

    @contextmanager
    def transaction(self):
        self._check_process()
        with self._lock:
            self._check_process()
            if self._owner is not None:
                raise RuntimeError('nested authentication transactions are not supported')
            try:
                try:
                    self._connect()
                except ValueError:
                    raise AuthenticationUnavailable('invalid private SQLite authentication store')
                self._query('BEGIN IMMEDIATE')
                self._owner = threading.current_thread().ident
                yield self
                self._connection.commit()
            except (sqlite3.Error, OSError, TypeError):
                raise AuthenticationUnavailable('SQLite authentication transaction failed')
            finally:
                # Closing an uncommitted connection rolls it back, including on
                # BaseException or a failed commit. No reconnect, retry or replay.
                self._owner = None
                try:
                    if self._connection is not None:
                        self._connection.close()
                except sqlite3.Error:
                    raise AuthenticationUnavailable('SQLite authentication close failed')
                finally:
                    self._cursor = None
                    self._connection = None

    def _check(self, table, key=None):
        self._check_process()
        if self._owner != threading.current_thread().ident:
            raise RuntimeError('authentication store operations require a transaction')
        if table not in STORE_TABLES:
            raise ValueError('unknown authentication namespace')
        if key is not None and (not isinstance(key, string_types) or not key or len(key) > MAX_KEY_LENGTH):
            raise ValueError('invalid authentication record key')

    @staticmethod
    def _decode(payload):
        try:
            if len(payload.encode('utf-8')) > MAX_RECORD_BYTES:
                raise ValueError()
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise AuthenticationUnavailable('invalid SQLite authentication record')

    def get(self, table, key):
        self._check(table, key)
        row = self._query('SELECT payload FROM auth_records WHERE namespace=? AND record_key=?', (table, key)).fetchone(raw=True)
        return self._decode(row[0]) if row else None

    def put(self, table, key, value):
        self._check(table, key)
        if not isinstance(value, dict):
            raise ValueError('authentication records must be JSON mappings')
        payload = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        if len(payload.encode('utf-8')) > MAX_RECORD_BYTES:
            raise ValueError('authentication record is too large')
        self._query('INSERT OR REPLACE INTO auth_records (namespace, record_key, payload) VALUES (?, ?, ?)',
                                 (table, key, payload))

    def delete(self, table, key):
        self._check(table, key)
        self._query('DELETE FROM auth_records WHERE namespace=? AND record_key=?', (table, key))

    def items(self, table):
        self._check(table)
        rows = self._query('SELECT record_key, payload FROM auth_records WHERE namespace=? ORDER BY record_key', (table,)).fetchall(raw=True)
        return [(key, self._decode(payload)) for key, payload in rows]

    def close(self):
        if self._pid != os.getpid():
            raise AuthenticationUnavailable('authentication store cannot be closed in a forked child')
        with self._lock:
            if self._owner is not None:
                raise RuntimeError('cannot close an active authentication transaction')
            self._closed = True
