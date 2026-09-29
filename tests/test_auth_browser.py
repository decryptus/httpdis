"""Browser policy against real session services; no framework request dependency."""
import unittest
from httpdis.auth_backend import LocalAuthService, MemoryAuthStore
from httpdis.auth_browser import BrowserAuthProvider, browser_origin
from httpdis.authentication import AuthenticationDenied, AuthenticationRequest
from test_auth_backend import FixturePasswords


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.service = LocalAuthService(MemoryAuthStore(), FixturePasswords(), clock=lambda: self.now,
                                        session_ttl=100, idle_ttl=20)
        self.service.provision('alice', 'correct-password', ['read', 'run'])
        self.provider = BrowserAuthProvider(self.service, 'https://auton.example', 'autond')

    def request(self, method='GET', cookie=None, csrf=None, **headers):
        values = {'host': 'auton.example', 'origin': 'https://auton.example',
                  'content-type': 'application/json', 'sec-fetch-site': 'same-origin'}
        if cookie is not None:
            values['cookie'] = cookie
        if csrf is not None:
            values['x-csrf-token'] = csrf
        values.update(headers)
        return AuthenticationRequest(method, '/route', tuple((k, v) for k, v in values.items() if v is not None), '127.0.0.1')

    def login(self):
        return self.provider.login(self.request('POST'), 'alice', 'correct-password')

    def cookie(self, grant):
        return self.provider.cookie_name + '=' + grant.secret

    def test_login_cookie_csrf_logout_and_rotation(self):
        first = self.login()
        cookie = self.cookie(first)
        header = self.provider.cookie(first.secret, 100)
        self.assertTrue(header.startswith('__Host-autond-session='))
        for flag in ('HttpOnly', 'SameSite=Strict', 'Secure', 'Path=/', 'Max-Age=100'):
            self.assertIn(flag, header)
        self.assertNotIn('Domain', header)
        self.assertEqual(self.provider.authenticate(self.request(cookie=cookie)).principal, 'alice')
        for csrf in (None, 'wrong'):
            with self.assertRaises(AuthenticationDenied):
                self.provider.authenticate(self.request('POST', cookie, csrf))
        self.assertEqual(self.provider.authenticate(self.request('POST', cookie, first.csrf)).method, 'session')
        second = self.provider.login(self.request('POST', cookie), 'alice', 'correct-password')
        self.assertNotEqual(second.secret, first.secret)
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(cookie=cookie))
        self.provider.logout(self.request('POST', self.cookie(second), second.csrf))
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(cookie=self.cookie(second)))
        self.assertIn('Max-Age=0', self.provider.expired_cookie())

    def test_origin_host_fetch_metadata_and_json_before_login(self):
        for headers in ({'origin': None}, {'origin': 'null'}, {'origin': 'https://evil.example'},
                        {'host': 'evil.example'}, {'sec-fetch-site': 'same-site'},
                        {'sec-fetch-site': 'cross-site'}, {'content-type': 'text/plain'},
                        {'content-type': 'application/x-www-form-urlencoded'}, {'authorization': 'Basic bad'}):
            with self.assertRaises(AuthenticationDenied):
                self.provider.login(self.request('POST', **headers), 'alice', 'correct-password')
        with self.service.store.transaction() as tx:
            self.assertEqual(tx.items('sessions'), [])
            self.assertEqual(tx.items('attempts'), [])
        grant = self.login()
        for headers in ({'origin': 'https://evil.example'}, {'host': 'evil.example'},
                        {'sec-fetch-site': 'same-site'}):
            with self.assertRaises(AuthenticationDenied):
                self.provider.authenticate(self.request(cookie=self.cookie(grant), **headers))
        self.assertEqual(self.provider.authenticate(self.request(cookie=self.cookie(grant), origin=None)).principal, 'alice')

    def test_no_ambiguous_cookie_or_credential_fallback(self):
        grant = self.login()
        token = self.service.issue_token('alice', ['read'], 20)
        authorization = 'Bearer ' + token.secret
        request = self.request(authorization=authorization, origin=None, **{'sec-fetch-site': None})
        self.assertEqual(self.provider.authenticate(request).method, 'token')
        for cookie in (self.cookie(grant) + '; ' + self.cookie(grant),
                       self.provider.cookie_name + '=bad', 'x=' + 'a' * 9000):
            with self.assertRaises(AuthenticationDenied):
                self.provider.authenticate(self.request(cookie=cookie))
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(cookie=self.cookie(grant), authorization=authorization))
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(authorization='Basic ignored'))
        request = self.request('POST')
        duplicate = request._replace(headers=request.headers + (('origin', 'https://auton.example'),))
        with self.assertRaises(AuthenticationDenied):
            self.provider.login(duplicate, 'alice', 'correct-password')

    def test_session_expiry_revocation_and_principal_scopes_are_shared(self):
        grant = self.login()
        self.now += 21
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(cookie=self.cookie(grant)))
        grant = self.login()
        self.service.disable('alice')
        with self.assertRaises(AuthenticationDenied):
            self.provider.authenticate(self.request(cookie=self.cookie(grant)))

    def test_origin_configuration_and_loopback_development(self):
        self.assertEqual(browser_origin('https://Auton.Example:443'), 'https://auton.example')
        for origin in ('http://remote.example', 'http://localhost', 'https://x/', 'https://x?',
                       'https://x#', 'https://user:pass@x', 'https://x:0', 'https://x:70000',
                       'https://x:\n', 'https://x\\evil', '', None):
            with self.assertRaises(ValueError):
                browser_origin(origin)
        local = BrowserAuthProvider(self.service, 'http://127.0.0.1:8666', 'autond')
        self.assertEqual(local.cookie_name, 'autond-session')
        self.assertNotIn('Secure', local.cookie('a' * 43, 10))
        self.assertEqual(browser_origin('http://[::1]:8666'), 'http://[::1]:8666')
