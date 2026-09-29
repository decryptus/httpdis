# -*- coding: utf-8 -*-
"""Storage-injected local authentication services; no HTTP or application imports."""
import base64
import copy
import hashlib
import hmac
import logging
import math
import os
import threading
import time
from collections import namedtuple
from contextlib import contextmanager

from six import string_types
from .authentication import (Identity, AuthenticationDenied, AuthenticationUnavailable,
                             AuthenticationProvider)

LOG = logging.getLogger(__name__)
STORE_TABLES = frozenset(('accounts', 'sessions', 'tokens', 'attempts'))
MAX_PASSWORD_BYTES = 1024
MIN_PASSWORD_LENGTH = 12
MAX_OPAQUE_LENGTH = 128
DEFAULT_SESSION_TTL = 28800
DEFAULT_IDLE_TTL = 1800
MAX_TOKEN_TTL = 2592000
DEFAULT_CAPACITY = 4096
ATTEMPT_WINDOW = 60
ACCOUNT_ATTEMPTS = 5
PEER_ATTEMPTS = 20
GLOBAL_ATTEMPTS = 100
MAX_HASH_WORKERS = 2


def _opaque():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')


def _digest(value):
    if not isinstance(value, string_types) or not value or len(value) > MAX_OPAQUE_LENGTH:
        raise AuthenticationDenied()
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _positive(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (math.isnan(value) or math.isinf(value)) or not 0 < value <= maximum:
        raise ValueError('invalid authentication duration')
    return value


def _password(value, creating=False):
    if not isinstance(value, string_types) or len(value.encode('utf-8')) > MAX_PASSWORD_BYTES or '\x00' in value:
        raise ValueError('invalid password')
    if creating and len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError('password must contain at least 12 characters')
    return value


class SessionGrant(namedtuple('_SessionGrant', 'secret csrf expires_at identity')):
    __slots__ = ()

    def __repr__(self):
        return 'SessionGrant(<redacted>)'


class TokenGrant(namedtuple('_TokenGrant', 'secret credential_id expires_at')):
    __slots__ = ()

    def __repr__(self):
        return 'TokenGrant(<redacted>)'


class MemoryAuthStore(object):
    """Explicit single-process store. Never selected implicitly by the service.

    transaction() must serialize the entire block and roll back on exceptions.
    Within it adapters implement get/put/delete/items with detached values.
    Durable/multi-process adapters must provide the same atomicity across workers.
    """
    def __init__(self):
        self._tables = dict((name, {}) for name in STORE_TABLES)
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self):
        with self._lock:
            saved = copy.deepcopy(self._tables)
            try:
                yield self
            except Exception:
                self._tables = saved
                raise

    def get(self, table, key):
        return copy.deepcopy(self._tables[table].get(key))

    def put(self, table, key, value):
        self._tables[table][key] = copy.deepcopy(value)

    def delete(self, table, key):
        self._tables[table].pop(key, None)

    def items(self, table):
        return copy.deepcopy(list(self._tables[table].items()))


class Argon2Passwords(object):
    """Optional maintained Argon2id adapter. Install httpdis[auth] on Python 3.10+."""
    def __init__(self):
        from argon2 import PasswordHasher
        from argon2.low_level import Type
        self._hasher = PasswordHasher(type=Type.ID)

    def hash(self, password):
        return self._hasher.hash(_password(password, creating=True))

    def verify(self, encoded, password):
        from argon2.exceptions import VerifyMismatchError
        try:
            return self._hasher.verify(encoded, _password(password))
        except VerifyMismatchError:
            return False


class LocalAuthService(object):
    """Explicit store, password adapter, clock and optional metadata-only audit.

    Provisioning/token issuance methods are trusted administrative operations,
    not public HTTP endpoints. Consumers enforce authorization for those calls.
    No session cookies, browser login or MFA enrollment is implemented here.
    """
    def __init__(self, store, passwords, clock=time.time, audit=None,
                 session_ttl=DEFAULT_SESSION_TTL, idle_ttl=DEFAULT_IDLE_TTL,
                 capacity=DEFAULT_CAPACITY):
        self.store, self.passwords, self.clock, self.audit = store, passwords, clock, audit
        self.session_ttl = _positive(session_ttl, DEFAULT_SESSION_TTL)
        self.idle_ttl = _positive(idle_ttl, self.session_ttl)
        if isinstance(capacity, bool) or not isinstance(capacity, int) or not 1 <= capacity <= DEFAULT_CAPACITY:
            raise ValueError('invalid authentication capacity')
        self.capacity = capacity
        self._hash_slots = threading.BoundedSemaphore(MAX_HASH_WORKERS)
        self._dummy_hash = passwords.hash(_opaque())

    def _event(self, name, principal=None):
        if self.audit is not None:
            try:
                self.audit(name, principal=principal)
            except Exception:
                LOG.error('Authentication audit callback failed')

    def _purge(self, tx, now):
        for table in ('sessions', 'tokens', 'attempts'):
            for key, record in tx.items(table):
                if record['expires'] <= now or (table == 'sessions' and record['idle'] <= now):
                    tx.delete(table, key)

    def _space(self, tx, table):
        if len(tx.items(table)) >= self.capacity:
            raise AuthenticationUnavailable()

    def provision(self, principal, password, scopes=()):
        identity = Identity(principal, 'password', scopes)
        encoded = self.passwords.hash(_password(password, creating=True))
        with self.store.transaction() as tx:
            if tx.get('accounts', principal) is None:
                self._space(tx, 'accounts')
            tx.put('accounts', principal, {'hash': encoded, 'scopes': tuple(identity.scopes),
                                          'revision': _opaque(), 'enabled': True})
            for table in ('sessions', 'tokens'):
                for key, record in tx.items(table):
                    if record['principal'] == principal:
                        tx.delete(table, key)
        self._event('account.updated', principal)

    def disable(self, principal):
        with self.store.transaction() as tx:
            account = tx.get('accounts', principal)
            if account is None:
                raise ValueError('unknown account')
            account['enabled'], account['revision'] = False, _opaque()
            tx.put('accounts', principal, account)
            for table in ('sessions', 'tokens'):
                for key, record in tx.items(table):
                    if record['principal'] == principal:
                        tx.delete(table, key)
        self._event('account.disabled', principal)

    def _admit_login(self, principal, peer):
        now = self.clock()
        if not isinstance(peer, string_types) or not peer or len(peer) > 256:
            raise AuthenticationDenied()
        # Bound global work as well as attempts for each account and direct peer.
        keys = (('global', GLOBAL_ATTEMPTS),
                ('account:' + hashlib.sha256(principal.encode('utf-8')).hexdigest(), ACCOUNT_ATTEMPTS),
                ('peer:' + hashlib.sha256(peer.encode('utf-8')).hexdigest(), PEER_ATTEMPTS))
        allowed = True
        with self.store.transaction() as tx:
            self._purge(tx, now)
            for key, limit in keys:
                record = tx.get('attempts', key)
                if record is None:
                    if len(tx.items('attempts')) >= self.capacity:
                        allowed = False
                        continue
                    record = {'expires': now + ATTEMPT_WINDOW, 'count': 0}
                if record['count'] >= limit:
                    allowed = False
                record['count'] = min(record['count'] + 1, limit)
                tx.put('attempts', key, record)
        if not allowed:
            self._event('login.throttled')
            raise AuthenticationDenied()

    def login(self, principal, password, peer):
        try:
            Identity(principal, 'password')
            _password(password)
        except (ValueError, UnicodeError):
            raise AuthenticationDenied()
        self._admit_login(principal, peer)
        if not self._hash_slots.acquire(False):
            raise AuthenticationUnavailable()
        try:
            with self.store.transaction() as tx:
                account = tx.get('accounts', principal)
            enabled = account is not None and account['enabled']
            encoded = account['hash'] if enabled else self._dummy_hash
            valid = self.passwords.verify(encoded, password)
        finally:
            self._hash_slots.release()
        if not valid or not enabled:
            self._event('login.denied')
            raise AuthenticationDenied()
        now, secret, csrf = self.clock(), _opaque(), _opaque()
        with self.store.transaction() as tx:
            current = tx.get('accounts', principal)
            if current != account or not current['enabled']:
                raise AuthenticationDenied()
            self._purge(tx, now)
            self._space(tx, 'sessions')
            tx.put('sessions', _digest(secret), {'principal': principal, 'revision': account['revision'],
                'scopes': account['scopes'], 'expires': now + self.session_ttl,
                'idle': now + self.idle_ttl, 'csrf': _digest(csrf)})
        self._event('login.succeeded', principal)
        return SessionGrant(secret, csrf, now + self.session_ttl, Identity(principal, 'session', account['scopes']))

    def issue_token(self, principal, scopes, ttl):
        ttl = _positive(ttl, MAX_TOKEN_TTL)
        identity = Identity(principal, 'token', scopes)
        now, secret = self.clock(), _opaque()
        key = _digest(secret)
        with self.store.transaction() as tx:
            account = tx.get('accounts', principal)
            if not account or not account['enabled'] or not identity.scopes.issubset(account['scopes']):
                raise AuthenticationDenied()
            self._purge(tx, now)
            self._space(tx, 'tokens')
            tx.put('tokens', key, {'principal': principal, 'revision': account['revision'],
                                  'scopes': tuple(identity.scopes), 'expires': now + ttl})
        self._event('token.issued', principal)
        return TokenGrant(secret, key, now + ttl)

    def revoke_token(self, credential_id):
        with self.store.transaction() as tx:
            tx.delete('tokens', credential_id)
        self._event('token.revoked')

    def logout(self, secret):
        with self.store.transaction() as tx:
            tx.delete('sessions', _digest(secret))
        self._event('session.revoked')

    def _resolve(self, table, secret, csrf=None, mutation=False):
        now, key = self.clock(), _digest(secret)
        with self.store.transaction() as tx:
            self._purge(tx, now)
            record = tx.get(table, key)
            if record is None:
                raise AuthenticationDenied()
            account = tx.get('accounts', record['principal'])
            if not account or not account['enabled'] or account['revision'] != record['revision']:
                raise AuthenticationDenied()
            if mutation and not hmac.compare_digest(record['csrf'].encode('ascii'), _digest(csrf).encode('ascii')):
                raise AuthenticationDenied()
            if table == 'sessions':
                record['idle'] = min(now + self.idle_ttl, record['expires'])
                tx.put(table, key, record)
            scopes = set(record['scopes']).intersection(account['scopes'])
            return Identity(record['principal'], 'session' if table == 'sessions' else 'token', scopes)

    def authenticate_token(self, secret):
        try:
            return self._resolve('tokens', secret)
        except AuthenticationDenied:
            self._event('token.denied')
            raise

    def authenticate_session(self, secret, csrf=None, mutation=False):
        try:
            return self._resolve('sessions', secret, csrf, mutation)
        except AuthenticationDenied:
            self._event('session.denied')
            raise


class BearerAuthProvider(AuthenticationProvider):
    """Explicit token-only transport adapter; never accepts browser cookies/Basic."""
    challenge = 'Bearer'

    def __init__(self, service):
        self.service = service

    def authenticate(self, request):
        authorization = request.header('authorization')
        if not isinstance(authorization, string_types) or len(authorization) > MAX_OPAQUE_LENGTH + 7:
            raise AuthenticationDenied()
        scheme, separator, secret = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not separator or not secret:
            raise AuthenticationDenied()
        return self.service.authenticate_token(secret)
