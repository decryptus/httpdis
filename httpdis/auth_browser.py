# -*- coding: utf-8 -*-
"""Opt-in browser transport policy over an application-owned LocalAuthService.

No routes, database paths, proxy trust or default backend are installed here.
The embedding server must expose login/logout, bound JSON bodies, disable CORS
and serve the configured public HTTPS origin (HTTP is local development only).
"""
import re
from six import string_types
from six.moves.urllib.parse import urlsplit
from .authentication import AuthenticationDenied, AuthenticationProvider, AUTH_HEADER_NAMES
from .auth_backend import BearerAuthProvider

SAFE_METHODS = frozenset(('GET', 'HEAD'))
MAX_COOKIE_BYTES = 8192
COOKIE_PREFIX_PATTERN = re.compile(r'^[a-z][a-z0-9-]{0,39}$')
OPAQUE_PATTERN = re.compile(r'^[A-Za-z0-9_-]{43}$')
ORIGIN_AUTHORITY_PATTERN = re.compile(r'^[A-Za-z0-9.\-:\[\]]+$')
LOOPBACK_HOSTS = frozenset(('127.0.0.1', '::1'))


def browser_origin(value):
    """Validate and canonicalize an explicit public origin; never trust Forwarded."""
    try:
        if (not isinstance(value, string_types) or not value or len(value) > 2048
                or any(ord(c) <= 32 or ord(c) >= 127 for c in value)):
            raise ValueError()
        parsed = urlsplit(value)
        if (parsed.scheme not in ('https', 'http') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment or '?' in value or '#' in value
                or not ORIGIN_AUTHORITY_PATTERN.match(parsed.netloc)
                or parsed.netloc.endswith(':')):
            raise ValueError()
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        if parsed.scheme == 'http' and parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError()
        host = parsed.hostname.lower()
        authority = '[%s]' % host if ':' in host else host
        if port is not None and port != (443 if parsed.scheme == 'https' else 80):
            authority += ':%s' % port
        return parsed.scheme + '://' + authority
    except (ValueError, TypeError):
        raise ValueError('browser origin must be HTTPS, or HTTP on 127.0.0.1/::1, without a path')


class BrowserAuthProvider(AuthenticationProvider):
    """Cookies for browsers, Bearer for explicit API callers, never fallback.

    Session secrets stay in HttpOnly cookies. The login grant's separate CSRF
    value must be sent in X-CSRF-Token for every mutation, including logout.
    Cookie and Bearer credentials cannot be combined in one request.
    """
    challenge = 'Bearer'

    def __init__(self, service, origin, cookie_prefix='httpdis'):
        if (not isinstance(cookie_prefix, string_types)
                or not COOKIE_PREFIX_PATTERN.match(cookie_prefix)
                or COOKIE_PREFIX_PATTERN.match(cookie_prefix).end() != len(cookie_prefix)):
            raise ValueError('invalid cookie prefix')
        self.service = service
        self.origin = browser_origin(origin)
        self.authority = urlsplit(self.origin).netloc
        self.secure = self.origin.startswith('https://')
        self.cookie_name = ('__Host-' if self.secure else '') + cookie_prefix + '-session'
        self.bearer = BearerAuthProvider(service)

    def require_browser(self, request, mutation=False):
        for name in AUTH_HEADER_NAMES:
            request.header(name)  # Reject duplicate security headers on public login too.
        if request.header('host', '').lower() != self.authority:
            raise AuthenticationDenied()
        origin = request.header('origin')
        if origin is not None and origin != self.origin:
            raise AuthenticationDenied()
        if request.header('sec-fetch-site') not in (None, 'same-origin', 'none'):
            raise AuthenticationDenied()
        if mutation:
            ctype = request.header('content-type', '').split(';', 1)[0].strip().lower()
            if origin != self.origin or ctype != 'application/json':
                raise AuthenticationDenied()

    def session_secret(self, request):
        cookie = request.header('cookie', '')
        if not isinstance(cookie, string_types) or len(cookie) > MAX_COOKIE_BYTES:
            raise AuthenticationDenied()
        values = []
        for part in cookie.split(';'):
            name, sep, value = part.strip().partition('=')
            if name == self.cookie_name:
                if not sep:
                    raise AuthenticationDenied()
                values.append(value)
        if not values:
            return None
        if len(values) != 1 or not self._opaque(values[0]):
            raise AuthenticationDenied()
        return values[0]

    @staticmethod
    def _opaque(value):
        return (isinstance(value, string_types) and len(value) == 43
                and OPAQUE_PATTERN.match(value) is not None)

    def authenticate(self, request):
        secret = self.session_secret(request)
        if request.header('authorization') is not None:
            if secret is not None:
                raise AuthenticationDenied()
            if request.header('origin') is not None or request.header('sec-fetch-site') is not None:
                self.require_browser(request, request.method not in SAFE_METHODS)
            return self.bearer.authenticate(request)
        mutation = request.method not in SAFE_METHODS
        self.require_browser(request, mutation)
        if secret is None:
            raise AuthenticationDenied()
        return self.service.authenticate_session(secret, request.header('x-csrf-token'), mutation)

    def login(self, request, principal, password):
        self.require_browser(request, mutation=True)
        if request.method != 'POST' or request.header('authorization') is not None:
            raise AuthenticationDenied()
        previous = self.session_secret(request)
        grant = self.service.login(principal, password, request.peer)
        # Never adopt a supplied session identifier. Reauthentication rotates it.
        if previous is not None:
            try:
                self.service.logout(previous)
            except Exception:
                self.service.logout(grant.secret)
                raise
        return grant

    def logout(self, request):
        if request.method != 'POST' or request.header('authorization') is not None:
            raise AuthenticationDenied()
        self.authenticate(request)
        self.service.logout(self.session_secret(request))

    def cookie(self, secret, max_age):
        if not self._opaque(secret) or type(max_age) is not int or max_age < 0:
            raise ValueError('invalid session cookie')
        return '%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s' % (
            self.cookie_name, secret, max_age, '; Secure' if self.secure else '')

    def expired_cookie(self):
        return '%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s' % (
            self.cookie_name, '; Secure' if self.secure else '')
