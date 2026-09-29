# -*- coding: utf-8 -*-
"""Provider contract independent of the HTTP server and credential storage.

This module deliberately has no default account database, file path, password
algorithm or session store. The embedding daemon constructs and owns providers.
"""
from collections import namedtuple
from six import string_types

MAX_PRINCIPAL_LENGTH = 256
MAX_AUTH_METHOD_LENGTH = 64
MAX_SCOPES = 128
MAX_SCOPE_LENGTH = 256
AUTH_HEADER_NAMES = frozenset(('authorization', 'cookie', 'origin', 'host',
                               'x-csrf-token', 'sec-fetch-site', 'content-type', 'referer'))


def _valid_text(value, limit):
    return (isinstance(value, string_types) and 0 < len(value) <= limit
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


class Identity(namedtuple('_Identity', 'principal method scopes')):
    """Verified identity; applications still enforce their business permissions."""
    __slots__ = ()

    def __new__(cls, principal, method, scopes=()):
        if not _valid_text(principal, MAX_PRINCIPAL_LENGTH):
            raise ValueError('invalid authentication principal')
        if not _valid_text(method, MAX_AUTH_METHOD_LENGTH):
            raise ValueError('invalid authentication method')
        if not isinstance(scopes, (tuple, list, set, frozenset)) or len(scopes) > MAX_SCOPES:
            raise ValueError('invalid authentication scopes')
        if any(not _valid_text(scope, MAX_SCOPE_LENGTH) for scope in scopes):
            raise ValueError('invalid authentication scope')
        return super(Identity, cls).__new__(cls, principal, method, frozenset(scopes))


class AuthenticationRequest(namedtuple('_AuthenticationRequest', 'method path headers peer')):
    """Explicit request values; no handler, payload, mutable headers or proxy trust.

    headers is an immutable sequence of lower-case name/value pairs. Providers
    must not log these values: Authorization and Cookie contain credentials.
    """
    __slots__ = ()

    def __repr__(self):
        return 'AuthenticationRequest(<redacted>)'

    def header(self, name, default=None):
        values = [value for key, value in self.headers if key == name.lower()]
        if len(values) > 1:
            raise AuthenticationDenied()
        return values[0] if values else default


class AuthenticationDenied(Exception):
    """Missing, expired, revoked or invalid credentials; wire response is generic."""


class AuthenticationUnavailable(Exception):
    """Backend unavailable; must never fall back to anonymous or legacy Basic."""


class AuthenticationProvider(object):
    """Implemented by a daemon adapter. Instances must support concurrent calls.

    authenticate(request) returns Identity, or None / raises AuthenticationDenied.
    An unavailable backend raises AuthenticationUnavailable. A provider owns its
    account/session/token adapters; HTTPdis neither discovers nor closes them.
    challenge is optional, fixed trusted configuration (e.g. 'Bearer').
    """
    challenge = None

    def authenticate(self, request):
        raise NotImplementedError()
