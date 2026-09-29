"""Durable authentication with real SQLite via Sonicprobe AnySQL."""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from httpdis.auth_sqlite import SQLiteAuthStore, SCHEMA_VERSION
from httpdis.auth_backend import LocalAuthService
from httpdis.authentication import AuthenticationDenied, AuthenticationUnavailable
from test_auth_backend import FixturePasswords


class SQLiteStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.filename = os.path.join(self.directory, 'auth ?#%.db')
        self.store = SQLiteAuthStore(self.filename, timeout=0.05)
        self.addCleanup(self.store.close)

    def service(self, store=None):
        return LocalAuthService(store or self.store, FixturePasswords(), clock=lambda: 1000)

    def test_credentials_sessions_revocation_and_limits_survive_reopening(self):
        service = self.service()
        service.provision('alice', 'correct-password', ['read', 'run'])
        session = service.login('alice', 'correct-password', 'local')
        token = service.issue_token('alice', ['read'], 60)
        for _ in range(5):
            with self.assertRaises(AuthenticationDenied):
                service.login('unknown', 'incorrect-password', 'local')
        self.store.close()
        reopened = SQLiteAuthStore(self.filename)
        self.addCleanup(reopened.close)
        other = self.service(reopened)
        self.assertEqual(other.authenticate_token(token.secret).principal, 'alice')
        self.assertEqual(other.authenticate_session(session.secret, session.csrf, True).principal, 'alice')
        other.provision('unknown', 'correct-password', [])
        with self.assertRaises(AuthenticationDenied):
            other.login('unknown', 'correct-password', 'local')
        other.revoke_token(token.credential_id)
        with self.assertRaises(AuthenticationDenied):
            other.authenticate_token(token.secret)
        other.disable('alice')
        with self.assertRaises(AuthenticationDenied):
            other.authenticate_session(session.secret)
        with open(self.filename, 'rb') as stream:
            data = stream.read()
        for secret in (session.secret, session.csrf, token.secret, 'correct-password'):
            self.assertNotIn(secret.encode(), data)

    def test_atomic_rollback_and_detached_json_values(self):
        with self.store.transaction() as tx:
            tx.put('accounts', 'alice', {'scopes': ['read']})
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as tx:
                tx.put('accounts', 'bob', {})
                tx.delete('accounts', 'alice')
                raise RuntimeError('rollback')
        with self.store.transaction() as tx:
            record = tx.get('accounts', 'alice')
            record['scopes'].append('run')
            self.assertEqual(tx.items('accounts'), [('alice', {'scopes': ['read']})])
            self.assertIsNone(tx.get('accounts', 'bob'))
            with self.assertRaises(RuntimeError):
                with self.store.transaction():
                    pass
        with self.assertRaises(RuntimeError):
            self.store.get('accounts', 'alice')

    def test_new_process_reads_committed_state_without_http_interfaces(self):
        with self.store.transaction() as tx:
            tx.put('accounts', 'alice', {'scopes': ['read']})
        code = '''
import sys
try:
    import builtins
except ImportError:
    import __builtin__ as builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name in ('dwho', 'httpdis.httpdis', 'curses', 'argparse'):
        raise AssertionError(name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from httpdis.auth_sqlite import SQLiteAuthStore
store = SQLiteAuthStore(sys.argv[1])
with store.transaction() as tx:
    assert tx.get('accounts', 'alice') == {'scopes': ['read']}
store.close()
'''
        process = subprocess.Popen([sys.executable, '-c', code, self.filename],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stderr)

    def test_concurrent_threads_and_instances_serialize_updates(self):
        other = SQLiteAuthStore(self.filename, timeout=5)
        self.addCleanup(other.close)
        self.store.close()
        self.store = SQLiteAuthStore(self.filename, timeout=5)
        self.addCleanup(self.store.close)
        with self.store.transaction() as tx:
            tx.put('attempts', 'counter', {'count': 0})
        failures = []
        def increment(store):
            try:
                for _ in range(10):
                    with store.transaction() as tx:
                        value = tx.get('attempts', 'counter')
                        value['count'] += 1
                        tx.put('attempts', 'counter', value)
            except Exception as error:
                failures.append(error)
        workers = [threading.Thread(target=increment, args=(store,))
                   for store in (self.store, self.store, other, other)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        with self.store.transaction() as tx:
            self.assertEqual(tx.get('attempts', 'counter')['count'], 40)

    def test_lock_timeout_and_failed_commit_never_replay(self):
        raw = sqlite3.connect(self.filename)
        try:
            raw.execute('BEGIN IMMEDIATE')
            with self.assertRaises(AuthenticationUnavailable):
                with self.store.transaction():
                    self.fail('locked transaction entered')
        finally:
            raw.close()
        with self.assertRaises(AuthenticationUnavailable):
            with self.store.transaction() as tx:
                tx.put('accounts', 'alice', {})
                tx._connection.close()
        with self.store.transaction() as tx:
            self.assertIsNone(tx.get('accounts', 'alice'))
        with mock.patch('httpdis.auth_sqlite.anysql.connect_by_uri', side_effect=TypeError('old version')):
            with self.assertRaises(AuthenticationUnavailable):
                with self.store.transaction():
                    self.fail('legacy connection accepted')

    def test_private_file_directory_symlink_and_replacement(self):
        self.assertEqual(os.stat(self.filename).st_mode & 0o777, 0o600)
        os.chmod(self.filename, 0o644)
        with self.assertRaises(AuthenticationUnavailable):
            SQLiteAuthStore(self.filename)
        os.chmod(self.filename, 0o600)
        link = os.path.join(self.directory, 'link.db')
        os.symlink(self.filename, link)
        with self.assertRaises(AuthenticationUnavailable):
            SQLiteAuthStore(link)
        os.chmod(self.directory, 0o777)
        try:
            with self.assertRaises(AuthenticationUnavailable):
                SQLiteAuthStore(self.filename)
        finally:
            os.chmod(self.directory, 0o700)
        os.rename(self.filename, self.filename + '.old')
        replacement = SQLiteAuthStore(self.filename)
        replacement.close()
        with self.assertRaises(AuthenticationUnavailable):
            with self.store.transaction():
                self.fail('replacement accepted')

    def test_incompatible_schema_and_invalid_record_fail_closed(self):
        raw = sqlite3.connect(self.filename)
        raw.execute('PRAGMA user_version=999')
        raw.close()
        with self.assertRaises(AuthenticationUnavailable):
            SQLiteAuthStore(self.filename)
        raw = sqlite3.connect(self.filename)
        raw.execute('PRAGMA user_version=%d' % SCHEMA_VERSION)
        raw.execute('DROP TABLE auth_records')
        raw.execute('CREATE TABLE auth_records (namespace TEXT, record_key TEXT, payload TEXT)')
        raw.commit()
        raw.close()
        with self.assertRaises(AuthenticationUnavailable):
            SQLiteAuthStore(self.filename)
        self.store.close()
        os.unlink(self.filename)
        new = SQLiteAuthStore(self.filename)
        self.addCleanup(new.close)
        raw = sqlite3.connect(self.filename)
        raw.execute('INSERT INTO auth_records VALUES (?, ?, ?)', ('accounts', 'alice', 'not JSON'))
        raw.commit()
        raw.close()
        with self.assertRaises(AuthenticationUnavailable):
            with new.transaction() as tx:
                tx.get('accounts', 'alice')

    def test_lifecycle_validation_and_record_bounds(self):
        for timeout in (0, -1, True, float('nan'), float('inf'), 31):
            with self.assertRaises(ValueError):
                SQLiteAuthStore(self.filename, timeout=timeout)
        with self.store.transaction() as tx:
            for table, key, value in (('unknown', 'x', {}), ('accounts', '', {}),
                                      ('accounts', 'x', []), ('accounts', 'x', {'data': 'x' * 65536})):
                with self.assertRaises(ValueError):
                    tx.put(table, key, value)
            with self.assertRaises(RuntimeError):
                self.store.close()
        with mock.patch('httpdis.auth_sqlite.os.getpid', return_value=-1):
            with self.assertRaises(AuthenticationUnavailable):
                with self.store.transaction():
                    pass
        self.store.close()
        self.store.close()
        with self.assertRaises(AuthenticationUnavailable):
            with self.store.transaction():
                pass
