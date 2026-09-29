"""Injected provider compatibility and isolation, using actual HTTP servers."""
import json
import os
import subprocess
import sys
import threading
import unittest

from six.moves import http_client
from httpdis import authentication as a
from httpdis import httpdis as h
from httpdis.ext import httpdis_json as j


class FixtureProvider(a.AuthenticationProvider):
    challenge = 'Bearer'

    def __init__(self, store):
        self.store = store
        self.last_request = None

    def authenticate(self, request):
        self.last_request = request
        credential = request.header('authorization') or request.header('cookie')
        if credential == 'Bearer broken':
            raise RuntimeError('SECRET backend connection string')
        if credential == 'Bearer invalid-result':
            return 'alice'
        return self.store.get(credential)


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.errors = []
        self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for context, thread in self.servers:
            context.stop()
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])

    def start(self, provider):
        context = j.HttpServerContext()
        ready = threading.Event()
        def identity(request):
            values = request.get_server_vars()
            verified = values['HTTP_AUTH_IDENTITY']
            return {'user': values['HTTP_AUTH_USER'], 'method': verified.method,
                    'scopes': sorted(verified.scopes), 'password_present': 'HTTP_AUTH_PASSWD' in values}
        context.register(identity, 'GET', name='identity', to_auth=True, at_start=lambda options: ready.set())
        context.register(identity, 'POST', name='identity', to_auth=True)
        context.register(identity, 'GET', name='admin', to_auth=['admin'])
        context.init({'listen_addr': '127.0.0.1', 'listen_port': 0, 'auth_provider': provider,
                      'max_workers': 2})
        def run():
            try:
                context.run()
            except Exception as error:
                self.errors.append(error)
                ready.set()
        thread = threading.Thread(target=run)
        thread.daemon = True
        self.servers.append((context, thread))
        thread.start()
        self.assertTrue(ready.wait(3))
        self.assertEqual(self.errors, [])
        return context

    def request(self, context, credential=None, path='/identity', method='GET', cookie=False):
        connection = http_client.HTTPConnection('127.0.0.1', context.server.server_port, timeout=3)
        headers = {'Content-Type': 'application/json', 'X-Forwarded-User': 'admin'}
        if credential:
            headers['Cookie' if cookie else 'Authorization'] = credential
        try:
            connection.request(method, path, body='{}' if method == 'POST' else None, headers=headers)
            response = connection.getresponse()
            return response.status, response.read(), dict((k.lower(), v) for k, v in response.getheaders())
        finally:
            connection.close()

    def test_two_servers_use_separate_supplied_stores_and_revocation(self):
        left_store = {'Bearer left': a.Identity('alice', 'token', ['read'])}
        right_store = {'sid=right': a.Identity('bob', 'session', ['execute'])}
        left_provider, right_provider = FixtureProvider(left_store), FixtureProvider(right_store)
        left, right = self.start(left_provider), self.start(right_provider)
        for context, credential, user, method, scopes, cookie in (
                (left, 'Bearer left', 'alice', 'token', ['read'], False),
                (right, 'sid=right', 'bob', 'session', ['execute'], True)):
            status, body, headers = self.request(context, credential, cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body.decode()), {'user': user, 'method': method,
                                                       'scopes': scopes, 'password_present': False})
        self.assertEqual(self.request(right, 'Bearer left')[0], 401)
        self.assertEqual(self.request(left, 'sid=right', cookie=True)[0], 401)
        left_store.clear()
        self.assertEqual(self.request(left, 'Bearer left')[0], 401)
        self.assertEqual(self.request(right, 'sid=right', cookie=True)[0], 200)
        self.assertEqual(left_provider.last_request.peer, '127.0.0.1')
        self.assertIsNone(left_provider.last_request.header('x-forwarded-user'))
        self.assertNotIn('Bearer', repr(left_provider.last_request))

    def test_denial_failure_and_route_allowlist_are_distinct(self):
        context = self.start(FixtureProvider({'Bearer good': a.Identity('alice', 'token')}))
        self.assertEqual(self.request(context, 'Bearer good', path='/admin')[0], 403)
        self.assertEqual(self.request(context, 'Bearer good', method='POST')[0], 200)
        for credential, expected in ((None, 401), ('Bearer bad', 401),
                                     ('Bearer broken', 503), ('Bearer invalid-result', 503)):
            status, body, headers = self.request(context, credential)
            self.assertEqual(status, expected)
            self.assertNotIn(b'SECRET', body)
            if expected == 401:
                self.assertEqual(headers['www-authenticate'], 'Bearer')
        self.assertEqual(self.request(context, 'Bearer good')[0], 200)

    def test_ambiguous_headers_and_stale_identity_are_rejected(self):
        context = j.HttpServerContext()
        provider = FixtureProvider({'Bearer good': a.Identity('alice', 'token')})
        context.init({'auth_provider': provider})
        class Handler(context.bind_handler()):
            def __init__(self):
                pass
        handler = Handler()
        handler._SERVER = {'HTTP_AUTH_USER': 'admin', 'HTTP_AUTH_PASSWD': 'SECRET', 'HTTP_AUTH_IDENTITY': 'old'}
        handler.command, handler._path, handler.client_address = 'GET', '/identity', ('127.0.0.1', 123)
        class Headers(object):
            def items(self):
                return [('Authorization', 'Bearer good'), ('authorization', 'Bearer other')]
        handler.headers = Headers()
        with self.assertRaises(h.HttpReqError) as caught:
            handler.authenticate()
        self.assertEqual(caught.exception.code, 401)
        self.assertEqual(handler._SERVER, {})
        self.assertIsNone(provider.last_request)

    def test_configuration_is_explicit_and_preserves_legacy_defaults(self):
        context = h.HttpServerContext()
        self.assertIsNone(context.auth_provider)
        for options in ({'auth_provider': object()},
                        {'auth_provider': FixtureProvider({}), 'auth_basic_file': '/not-opened'}):
            with self.assertRaises(ValueError):
                context.init(options)
        provider = FixtureProvider({})
        provider.challenge = 'Bearer\r\nInjected: yes'
        with self.assertRaises(ValueError):
            context.init({'auth_provider': provider})
        provider.challenge = 'Bearer'
        context.init({'auth_provider': provider})
        self.assertIs(context.auth_provider, provider)
        context.init({})
        self.assertIsNone(context.auth_provider)

    def test_identity_is_immutable_and_scope_input_is_validated(self):
        identity = a.Identity('alice', 'session', ['read'])
        with self.assertRaises(AttributeError):
            identity.principal = 'admin'
        self.assertEqual(identity.scopes, frozenset(['read']))
        for scopes in ('read', [''], ['a'] * 129):
            with self.assertRaises(ValueError):
                a.Identity('alice', 'session', scopes)
        with self.assertRaises(ValueError):
            a.Identity('bad\nname', 'token')

    def test_contract_imports_without_http_or_application_interfaces(self):
        script = '''
import sys
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
from httpdis.authentication import Identity, AuthenticationProvider
class Provider(AuthenticationProvider):
    def authenticate(self, request):
        return Identity('alice', 'token', ['read'])
assert Provider().authenticate(None).scopes == frozenset(['read'])
''' % os.path.dirname(os.path.dirname(a.__file__))
        process = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
