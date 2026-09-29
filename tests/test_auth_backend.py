"""Local authentication behavior with explicit adapters and deterministic clocks."""
import hashlib
import importlib
import os
import subprocess
import sys
import threading
import json
from six.moves import http_client
import unittest

from httpdis import auth_backend as b
from httpdis.authentication import AuthenticationDenied, AuthenticationRequest, AuthenticationUnavailable


class FixturePasswords(object):
    """Test adapter only: never a production password implementation."""
    def hash(self, password):
        return 'fixture:' + hashlib.sha256(password.encode()).hexdigest()

    def verify(self, encoded, password):
        return encoded == self.hash(password)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.events = []
        self.store = b.MemoryAuthStore()
        self.service = b.LocalAuthService(self.store, FixturePasswords(), clock=lambda: self.now,
                                         audit=lambda event, **fields: self.events.append((event, fields)),
                                         session_ttl=100, idle_ttl=20)
        self.service.provision('alice', 'correct-password', ['read', 'run'])

    def test_session_idle_absolute_expiry_and_csrf(self):
        grant = self.service.login('alice', 'correct-password', '127.0.0.1')
        self.assertNotIn(grant.secret, repr(grant))
        self.assertEqual(self.service.authenticate_session(grant.secret).scopes, frozenset(['read', 'run']))
        for csrf in (None, '', 'incorrect'):
            with self.assertRaises(AuthenticationDenied):
                self.service.authenticate_session(grant.secret, csrf=csrf, mutation=True)
        self.assertEqual(self.service.authenticate_session(grant.secret, grant.csrf, True).principal, 'alice')
        for instant in (1019, 1038, 1057, 1076, 1095):
            self.now = instant
            self.service.authenticate_session(grant.secret)
        self.now = 1100
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_session(grant.secret)
        grant = self.service.login('alice', 'correct-password', '127.0.0.1')
        self.now += 20
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_session(grant.secret)

    def test_tokens_scopes_revocation_expiry_and_no_plaintext_storage(self):
        grant = self.service.issue_token('alice', ['read'], 10)
        self.assertNotIn(grant.secret, repr(grant))
        identity = self.service.authenticate_token(grant.secret)
        self.assertEqual(identity.scopes, frozenset(['read']))
        with self.assertRaises(AuthenticationDenied):
            self.service.issue_token('alice', ['maintenance'], 10)
        with self.store.transaction() as tx:
            self.assertNotIn(grant.secret, repr(tx.items('tokens')))
        self.service.revoke_token(grant.credential_id)
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_token(grant.secret)
        grant = self.service.issue_token('alice', [], 10)
        self.now += 10
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_token(grant.secret)

    def test_password_rotation_disable_logout_and_account_race(self):
        session = self.service.login('alice', 'correct-password', 'local')
        token = self.service.issue_token('alice', ['read'], 30)
        self.service.provision('alice', 'replacement-password', ['read'])
        for callback, secret in ((self.service.authenticate_token, token.secret),
                                 (self.service.authenticate_session, session.secret)):
            with self.assertRaises(AuthenticationDenied):
                callback(secret)
        session = self.service.login('alice', 'replacement-password', 'local')
        self.service.logout(session.secret)
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_session(session.secret)
        token = self.service.issue_token('alice', ['read'], 30)
        self.service.disable('alice')
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_token(token.secret)
        with self.assertRaises(AuthenticationDenied):
            self.service.login('alice', 'replacement-password', 'local')
        self.service.provision('alice', 'correct-password', ['read'])
        original = self.service.passwords.verify
        def race(encoded, password):
            self.service.disable('alice')
            return original(encoded, password)
        self.service.passwords.verify = race
        with self.assertRaises(AuthenticationDenied):
            self.service.login('alice', 'correct-password', 'local')

    def test_login_rate_limits_unknown_users_and_reset(self):
        for _ in range(5):
            with self.assertRaises(AuthenticationDenied):
                self.service.login('alice', 'wrong-password', 'local')
        with self.assertRaises(AuthenticationDenied):
            self.service.login('alice', 'correct-password', 'another-peer')
        self.now += 60
        self.service.login('alice', 'correct-password', 'local')
        for index in range(19):
            with self.assertRaises(AuthenticationDenied):
                self.service.login('unknown-' + str(index), 'wrong-password', 'local')
        with self.assertRaises(AuthenticationDenied):
            self.service.login('alice', 'correct-password', 'local')
        self.assertNotIn('correct-password', repr(self.events))

    def test_capacity_and_store_isolation(self):
        other = b.LocalAuthService(b.MemoryAuthStore(), FixturePasswords(), clock=lambda: self.now,
                                   capacity=3)
        other.provision('alice', 'correct-password', ['read'])
        grants = [other.issue_token('alice', ['read'], 10) for _ in range(3)]
        with self.assertRaises(AuthenticationUnavailable):
            other.issue_token('alice', ['read'], 10)
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_token(grants[0].secret)
        self.now += 10
        other.issue_token('alice', ['read'], 10)
        with self.assertRaises(ValueError):
            b.LocalAuthService(self.store, FixturePasswords(), idle_ttl=0)
        for ttl in (0, -1, float('nan'), float('inf'), True, b.MAX_TOKEN_TTL + 1):
            with self.assertRaises(ValueError):
                other.issue_token('alice', ['read'], ttl)

    def test_transaction_rollback_and_hash_concurrency_bound(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as tx:
                tx.delete('accounts', 'alice')
                raise RuntimeError('rollback')
        for _ in range(b.MAX_HASH_WORKERS):
            self.service._hash_slots.acquire()
        try:
            with self.assertRaises(AuthenticationUnavailable):
                self.service.login('alice', 'correct-password', 'local')
        finally:
            for _ in range(b.MAX_HASH_WORKERS):
                self.service._hash_slots.release()
        self.service.login('alice', 'correct-password', 'local')

    def test_bearer_provider_rejects_other_methods_and_reflects_revocation(self):
        provider = b.BearerAuthProvider(self.service)
        grant = self.service.issue_token('alice', ['read'], 10)
        def request(header):
            return AuthenticationRequest('GET', '/', (('authorization', header),), '127.0.0.1')
        self.assertEqual(provider.authenticate(request('Bearer ' + grant.secret)).principal, 'alice')
        for value in ('Basic xxx', '', None, 'Bearer ' + 'x' * 129):
            with self.assertRaises(AuthenticationDenied):
                provider.authenticate(request(value))
        self.service.revoke_token(grant.credential_id)
        with self.assertRaises(AuthenticationDenied):
            provider.authenticate(request('Bearer ' + grant.secret))

    def test_audit_failure_does_not_grant_or_revoke_access(self):
        def broken(*args, **kwargs):
            raise RuntimeError('private error')
        self.service.audit = broken
        session = self.service.login('alice', 'correct-password', 'local')
        self.service.logout(session.secret)
        with self.assertRaises(AuthenticationDenied):
            self.service.authenticate_session(session.secret)

    def test_argon2_adapter_when_optional_dependency_is_installed(self):
        try:
            importlib.import_module('argon2')
        except ImportError:
            if os.environ.get('HTTPDIS_REQUIRE_ARGON2') == '1':
                self.fail('auth extra must be installed in this CI job')
            self.skipTest('optional auth extra absent; mandatory real Argon2 test runs in modern CI')
        adapter = b.Argon2Passwords()
        encoded = adapter.hash('correct-password')
        self.assertTrue(encoded.startswith('$argon2id$'))
        self.assertTrue(adapter.verify(encoded, 'correct-password'))
        self.assertFalse(adapter.verify(encoded, 'wrong-password'))

    def test_real_http_server_uses_the_local_token_service(self):
        from httpdis.ext import httpdis_json as http
        context, ready, failures = http.HttpServerContext(), threading.Event(), []
        token = self.service.issue_token('alice', ['read'], 60)
        def identity(request):
            result = request.get_server_vars()['HTTP_AUTH_IDENTITY']
            return {'user': result.principal, 'scopes': sorted(result.scopes)}
        context.register(identity, 'GET', name='identity', to_auth=True,
                         at_start=lambda options: ready.set())
        context.init({'listen_addr': '127.0.0.1', 'listen_port': 0,
                      'auth_provider': b.BearerAuthProvider(self.service)})
        def run():
            try:
                context.run()
            except Exception as error:
                failures.append(error)
                ready.set()
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        try:
            self.assertTrue(ready.wait(3))
            self.assertEqual(failures, [])
            for expected in (200, 401):
                connection = http_client.HTTPConnection('127.0.0.1', context.server.server_port, timeout=3)
                try:
                    connection.request('GET', '/identity', headers={'Authorization': 'Bearer ' + token.secret})
                    response = connection.getresponse()
                    body = response.read()
                    self.assertEqual(response.status, expected)
                    if expected == 200:
                        self.assertEqual(json.loads(body.decode()), {'user': 'alice', 'scopes': ['read']})
                finally:
                    connection.close()
                self.service.revoke_token(token.credential_id)
        finally:
            context.stop()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    def test_backend_runs_without_http_interfaces(self):
        code = '''
import sys
import threading
import json
from six.moves import http_client
sys.path.insert(0, %r)
try:
    import builtins
except ImportError:
    import __builtin__ as builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name in ('httpdis.httpdis', 'dwho', 'curses', 'argparse'):
        raise AssertionError(name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from httpdis.auth_backend import LocalAuthService, MemoryAuthStore
class Passwords(object):
    def hash(self, password): return 'test-fixture:' + password
    def verify(self, encoded, password): return encoded == self.hash(password)
service = LocalAuthService(MemoryAuthStore(), Passwords())
service.provision('alice', 'correct-password', ['read'])
token = service.issue_token('alice', ['read'], 60)
assert service.authenticate_token(token.secret).principal == 'alice'
'''
        process = subprocess.Popen([sys.executable, '-c', code % os.path.dirname(os.path.dirname(b.__file__))],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
