# -*- coding: utf-8 -*-
# Copyright 2008-2019 The Wazo Authors
# SPDX-License-Identifier: GPL-3.0-or-later
"""httpsdis.httpsdis"""

# TODO: locks and implements SIGHUP (by reloading the configuration)

# TODO: add some teardown callbacks?
# maybe two stages:
#   - cb teardown stage 1
#   - wait for tread completion in this module
#   - cb teardown stage 2

# TODO: split backtraces in syslog when they are too long

import email.utils
import binascii
import threading
from hmac import compare_digest
import errno
import io
import json
import logging
import os
import select
import signal
import socket
import sys
import time
try:
    from time import monotonic
except ImportError:  # Python 2.7
    from monotonic import monotonic
#import weakref

import cgi
try:
    from cgi import escape as html_escape
except ImportError:
    from html import escape as html_escape

import re
try:
    from re import _pattern_type as RePatternType
except ImportError:
    from re import Pattern as RePatternType

from base64 import b64encode, b64decode
try:
    from crypt import crypt
except ImportError:
    from legacycrypt import crypt
from hashlib import sha1

from six import (BytesIO,
                 binary_type,
                 ensure_binary,
                 ensure_text,
                 integer_types,
                 iteritems,
                 reraise,
                 string_types)
from six.moves import http_cookies
from six.moves.urllib import parse as urlparse, request as urlrequest
from six.moves.BaseHTTPServer import BaseHTTPRequestHandler

import magic
from .authentication import (Identity, AuthenticationRequest,
                                    AuthenticationDenied, AuthenticationUnavailable,
                                    AUTH_HEADER_NAMES)

from sonicprobe import helpers
from sonicprobe.libs import urisup
from sonicprobe.libs.threading_tcp_server import KillableThreadingHTTPServer

from .auth_browser import browser_origin
from .content_disposition import build_header, parse_headers

from .config import (BUFFER_SIZE, # pylint: disable=unused-import
                     DEFAULT_CHARSET,
                     get_default_options)


LOG              = logging.getLogger('httpdis') # pylint: disable-msg=C0103
_DES_CRYPT_HASH = re.compile(r'[./0-9A-Za-z]{13}\Z')
_HTTP_VERSION = re.compile(r'HTTP/[0-9]+[.][0-9]+\Z')
_CONTENT_LENGTH = re.compile(r'[0-9]+\Z')
_QUERY_BRACKETS = re.compile(r'\[([^\]]*)\]')
MAX_QUERY_FIELDS = 1024
MAX_QUERY_DEPTH = 32
HEADER_READ_SECONDS = 10
BODY_GRACE_SECONDS = 10
BODY_BYTES_PER_SECOND = 32 * 1024
BODY_MAX_SECONDS = 120
_CORS_REQUEST_HEADERS = frozenset(('accept', 'authorization', 'content-type', 'x-requested-with'))
_CORS_PREFLIGHT_VARY = 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers'
_BODYLESS_CODES = (204, 205, 304)
_NO_LENGTH_CODES = (204, 304)

_METHODS         = ('HEAD',
                    'GET',
                    'DELETE',
                    'PATCH',
                    'POST',
                    'PUT')

_END_EXC_HEADERS = ('Cache-control',
                    'Connection',
                    'Content-type',
                    'Content-length',
                    'Pragma',
                    'Server')

_AUTH            = None
_COMMANDS        = {}
_NCMD            = {}
_RCMD            = {}
_HTTP_SERVER     = None
_KILLED          = False
_OPTIONS         = {}
DEFAULT_OPTIONS  = get_default_options()
_SERVER_VERSION_OPTIONS = ('server_version', 'sys_version')


class HttpListeningServer(KillableThreadingHTTPServer):
    """Apply this listener's TCP backlog before the base constructor calls listen."""
    def __init__(self, config, server_address, RequestHandlerClass,
                 bind_and_activate=True, name=None):
        backlog = config.get('listen_backlog', DEFAULT_OPTIONS['listen_backlog'])
        if isinstance(backlog, string_types) and backlog.isdigit():
            backlog = int(backlog)
        if (isinstance(backlog, bool) or not isinstance(backlog, integer_types)
                or not 0 <= backlog <= 2147483647):
            raise ValueError('listen_backlog must be an integer between 0 and 2147483647')
        self.request_queue_size = backlog
        KillableThreadingHTTPServer.__init__(self, config, server_address, RequestHandlerClass,
                                             bind_and_activate, name)


class Command(object): # pylint: disable=too-few-public-methods,useless-object-inheritance
    """
    Each registration results in an instance of this class being created.
    """
    def __init__(self,
                 name,
                 handler,
                 op,
                 safe_init,
                 at_start,
                 at_stop,
                 static,
                 root,
                 replacement,
                 charset,
                 content_type,
                 to_auth,
                 to_log,
                 max_body_size = None,
                 cors_origins = ()):
        if max_body_size is not None \
           and (isinstance(max_body_size, bool) \
                or not isinstance(max_body_size, integer_types) \
                or max_body_size < 0):
            raise ValueError("max_body_size must be a non-negative integer or None")

        if not isinstance(cors_origins, (list, tuple)):
            raise ValueError('cors_origins must be a list or tuple of explicit origins')
        self.cors_origins = frozenset(browser_origin(origin) for origin in cors_origins)
        self.max_body_size = max_body_size
        self.handler       = handler
        self.name          = name
        self.op            = op
        self.safe_init     = safe_init
        self.at_start      = at_start
        self.at_stop       = at_stop
        self.static        = static
        self.root          = root
        self.replacement   = replacement
        self.charset       = charset
        self.content_type  = content_type
        self.to_log        = to_log

        if isinstance(to_auth, (list, tuple)):
            self.auth_users = list(filter(helpers.has_len, to_auth))
            self.to_auth    = True
        else:
            self.auth_users = []
            self.to_auth    = bool(to_auth)


class HttpResponse(urlrequest.Request):
    def __init__(self, code=200, data="", headers=None, message=None, send_body=True):
        if headers is None:
            headers = {}

        urlrequest.Request.__init__(self, "http://127.0.0.1", data=data, headers=headers)
        self.code      = code
        self.send_body = send_body
        self.message   = message

    def get_code(self):
        return self.code

    def set_code(self, code):
        self.code = code
        return self

    def set_send_body(self, send_body):
        self.send_body = send_body
        return self

    def set_message(self, message):
        self.message = message
        return self

    def get_message(self):
        return self.message

    def is_send_body(self):
        return self.send_body

    def add_data(self, data):
        self.data = data # pylint: disable=attribute-defined-outside-init
        return self

    def add_header(self, key, val):
        urlrequest.Request.add_header(self, key, val)
        return self


class HttpResponseJson(HttpResponse):
    def __init__(self, code=200, data="", headers=None, message=None, send_body=True):
        if headers is None:
            headers = {}

        data = json.dumps(data)

        if not isinstance(headers, dict):
            headers = {}

        if headers.get('Content-type', '').split(';', 1)[0].strip() != 'application/json':
            headers['Content-type'] = 'application/json'

        HttpResponse.__init__(self, code, data, headers, message, send_body)


class HttpReqError(Exception):
    """
    Catched in HttpReqHandler.common_req() which calls .report().

    Used to implement the unicity of the response to a single request,
    in a consistent way.
    """

    def __init__(self, code, text=None, exc=None, headers=None, ctype=None):
        if headers is None:
            headers = {}

        self.code  = code
        self.text  = text
        self.exc   = exc
        self.ctype = ctype or 'msg'
        msg        = text or BaseHTTPRequestHandler.responses[code][1]

        if not isinstance(headers, dict):
            headers = {}
        self.headers = headers

        Exception.__init__(self, msg)

    def report(self, req_handler):
        "Send a response corresponding to this error to the client"
        if self.exc:
            req_handler.send_exception(self.code, self.exc, self.headers)
            return

        text = (self.text
                or BaseHTTPRequestHandler.responses[self.code][1]
                or "Unknown error")

        getattr(req_handler, "send_error_%s" % self.ctype, req_handler.send_error_msg)(self.code, text, self.headers)


class HttpReqErrJson(HttpReqError):
    def __init__(self, code, text=None, exc=None, headers=None):
        HttpReqError.__init__(self, code, text, exc, headers, ctype = 'json')


HTTP_RESPONSE_CLASS = HttpResponse
HTTP_REQERROR_CLASS = HttpReqError


class HttpAuthentication(object): # pylint: disable=useless-object-inheritance
    def __init__(self, htpasswd, realm=None, allow_legacy_hashes=False):
        if type(allow_legacy_hashes) is not bool:
            raise ValueError('auth_basic_allow_legacy_hashes must be a boolean')
        self.allow_legacy_hashes = allow_legacy_hashes
        self.htpasswd = htpasswd
        self.realm    = realm
        self.users    = {}
        self._credentials = threading.local()

    def parse_file(self):
        legacy_formats = set()
        with open(self.htpasswd, 'r') as stream:
            for line in stream:
                entry = line.strip()
                if not entry or entry.startswith('#') or entry.find(':') < 1:
                    continue
                user, secret = entry.split(':', 1)
                if not secret:
                    continue
                self.users[user] = secret
                if secret.startswith('{SHA}'):
                    legacy_formats.add('SHA-1')
                elif _DES_CRYPT_HASH.match(secret):
                    legacy_formats.add('DES')
        if legacy_formats:
            LOG.warning('Legacy Basic password hashes detected (%s). '
                        'These entries are %s. Replace the affected htpasswd entries.',
                        ', '.join(sorted(legacy_formats)),
                        'temporarily enabled' if self.allow_legacy_hashes else 'disabled')

        return self

    @property
    def user(self):
        return getattr(self._credentials, 'user', None)

    @property
    def passwd(self):
        """Compatibility accessor. The verifier retains only the username."""
        return None

    def valid_authorization(self, authorization):
        self._credentials.user = None
        try:
            kind, data = authorization.split(None, 1)
            if kind.lower() != 'basic':
                return False
            decoded = b64decode(ensure_binary(data.strip()))
            user, separator, passwd = decoded.partition(b':')
            if not separator:
                return False
            user = user.decode('utf-8')
            password = passwd.decode('utf-8')
        except (ValueError, TypeError, UnicodeError, binascii.Error):
            return False
        secret = self.users.get(user)
        if not secret:
            return False
        if not self.allow_legacy_hashes and (secret.startswith('{SHA}') or _DES_CRYPT_HASH.match(secret)):
            return False
        if secret.startswith('{SHA}'):
            calculated = '{SHA}' + b64encode(sha1(passwd).digest()).decode('ascii')
        else:
            calculated = crypt(password, secret)
        if not calculated or not compare_digest(ensure_binary(secret), ensure_binary(calculated)):
            return False
        self._credentials.user = user
        return True

    def unauthorized(self, req_error = None):
        if not req_error:
            req_error = HTTP_REQERROR_CLASS

        headers = {'WWW-Authenticate': 'Basic realm="%s"' % self.realm or ''}

        return req_error(code = 401, headers = headers)

    @staticmethod
    def forbidden(req_error = None):
        if not req_error:
            req_error = HTTP_REQERROR_CLASS

        return req_error(code = 403)


class _DeadlineSocketInput(io.RawIOBase):
    """Apply the phase budget on each receive, below any input buffering."""

    def __init__(self, connection):
        io.RawIOBase.__init__(self)
        self.connection = connection
        self.deadline = None

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.deadline is None:
            return self.connection.recv_into(buffer)
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise socket.timeout('Request read deadline exceeded')
        previous = self.connection.gettimeout()
        self.connection.settimeout(remaining if previous is None else min(remaining, previous))
        try:
            return self.connection.recv_into(buffer)
        finally:
            self.connection.settimeout(previous)


class HttpReqHandler(BaseHTTPRequestHandler):
    """
    Handle one HTTP request
    """

    _deadline_input = None
    header_read_seconds = HEADER_READ_SECONDS
    body_grace_seconds = BODY_GRACE_SECONDS
    body_bytes_per_second = BODY_BYTES_PER_SECOND
    body_max_seconds = BODY_MAX_SECONDS

    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self.rfile.close()
        self._deadline_input = _DeadlineSocketInput(self.connection)
        if self.rbufsize == 0:
            self.rfile = self._deadline_input
        else:
            size = self.rbufsize if self.rbufsize > 0 else io.DEFAULT_BUFFER_SIZE
            self.rfile = io.BufferedReader(self._deadline_input, size)

    def handle_one_request(self):
        if self._deadline_input is None:
            return BaseHTTPRequestHandler.handle_one_request(self)
        self._deadline_input.deadline = monotonic() + self.header_read_seconds
        try:
            return BaseHTTPRequestHandler.handle_one_request(self)
        except socket.timeout:
            self.close_connection = True
        finally:
            self._deadline_input.deadline = None

    def parse_request(self):
        try:
            return BaseHTTPRequestHandler.parse_request(self)
        finally:
            if self._deadline_input is not None:
                self._deadline_input.deadline = None

    _DEFAULT_CONTENT_TYPE   = 'text/plain'
    _ALLOWED_CONTENT_TYPES  = []
    _ALLOWED_MULTIPART_FORM = True
    _CLASS_HTTP_RESP        = HTTP_RESPONSE_CLASS
    _CLASS_REQ_ERROR        = HTTP_REQERROR_CLASS
    _FUNC_SEND_ERROR        = 'send_error_msgtxt'

    _SERVER                 = {}

    _to_log                 = True
    _cmd                    = None

    _path                   = None
    _payload                = None
    _payload_params         = None
    _query_params           = {}
    _fragment               = None


    def get_context(self):
        context = getattr(self, '_httpdis_context', None)
        if context is not None:
            return context
        return getattr(getattr(self, 'server', None), 'httpdis_context', _DEFAULT_CONTEXT)

    def build_response(self, code=200, data="", headers=None, message=None, send_body=True):
        return self._CLASS_HTTP_RESP(code, data, headers, message, send_body)

    def req_error(self, code, text=None, exc=None, headers=None):
        return self._CLASS_REQ_ERROR(code, text, exc, headers)

    def send_error_msg(self, code, message, headers=None):
        return getattr(self, self._FUNC_SEND_ERROR)(code, message, headers)

    def log_enabled(self):
        return self._to_log

    def get_server_vars(self):
        return self._SERVER

    def set_log(self, enable = True):
        self._to_log = bool(enable)
        return self

    def fragment(self):
        return self._fragment

    def get_cmd(self):
        return self._cmd

    def get_headers(self):
        if hasattr(self.headers, 'dict'):
            return self.headers.dict

        return dict(self.headers.items())

    def get_method(self):
        return self.command

    def get_path(self):
        return self._path

    def get_payload(self):
        return self._payload

    def payload_params(self):
        return self._payload_params

    def query_params(self):
        return self._query_params

    def version_string(self):
        return BaseHTTPRequestHandler.version_string(self).strip()

    def permit_ctype(self, ctype):
        if ctype:
            self._ALLOWED_CONTENT_TYPES += [ctype.lower()]
        return self

    def forbid_ctype(self, ctype):
        if ctype and ctype in self._ALLOWED_CONTENT_TYPES:
            self._ALLOWED_CONTENT_TYPES.remove(ctype.lower())
        return self

    def permit_multipart(self):
        self._ALLOWED_MULTIPART_FORM = True
        return self

    def forbid_multipart(self):
        self._ALLOWED_MULTIPART_FORM = False
        return self

    @staticmethod
    def parse_date(ims):
        """ Parse rfc1123, rfc850 and asctime timestamps and return UTC epoch. """
        try:
            ts = email.utils.parsedate_tz(ims)
            return time.mktime(ts[:8] + (0,)) - (ts[9] or 0) - time.timezone
        except (TypeError, ValueError, IndexError):
            return None

    def log_error(self, xformat, *args): # pylint: disable=arguments-differ
        """
        There is more information in log_request(), which is always called
        => do nothing
        """
        pass # pylint: disable=unnecessary-pass

    def log_request(self, code='-', size='-'):
        """Log a query-free request target, including on early parser errors."""
        fields = self.requestline.split()
        line = '<invalid request>'
        if (len(fields) in (2, 3) and fields[0] in _METHODS + ('OPTIONS',)
                and (len(fields) == 2 or _HTTP_VERSION.match(fields[2]))):
            target = fields[1].partition('?')[0].partition('#')[0]
            if target.startswith('/') and not target.startswith('//'):
                path = target
            elif target == '*':
                path = '*'
            else:
                # Absolute-form targets may contain authority credentials.
                # Never fall back to the original string on a parsing error.
                path = '-'
                try:
                    parsed = urlparse.urlsplit(target)
                    if parsed.netloc and parsed.scheme in ('', 'http', 'https'):
                        path = parsed.path or '/'
                except ValueError:
                    pass
            fields[1] = path
            line = ' '.join(fields)
        LOG.info("%r %s %s", line, code, size)

    def send_response(self, code, message=None, size='-'):
        """
        Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.
        """
        # pylint: disable-msg=W0221
        if self._to_log or LOG.isEnabledFor(logging.DEBUG):
            self.log_request(code, size)

        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''

        if self.request_version != 'HTTP/0.9':
            self.wfile.write(ensure_binary("%s %d %s\r\n"
                                           % (self.protocol_version, code, message)))
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def end_response(self, response):
        if not isinstance(response, HttpResponse):
            raise TypeError("Response must be HttpResponse instance: %r" % response)

        code = response.get_code()

        if code >= 200 and code not in _BODYLESS_CODES \
           and (response.is_send_body() or self.command == 'HEAD'):
            data = ensure_binary(response.data or "")
            clen = len(data)
        else:
            data = ""
            clen = 0

        self.send_response(code     = code,
                           size     = clen,
                           message  = response.get_message())

        if response.get_header('Content-type'):
            content_type = response.get_header('Content-type')
        elif self._cmd and self._cmd.content_type:
            content_type = self._cmd.content_type
        else:
            content_type = self._DEFAULT_CONTENT_TYPE

        self.send_header('Cache-Control', response.get_header('Cache-control') or 'no-cache')
        self.send_header('Pragma', response.get_header('Pragma') or 'no-cache')
        self.send_header('Connection', response.get_header('Connection') or 'close')
        self.send_header('Content-Type', content_type)
        if code >= 200 and code not in _NO_LENGTH_CODES:
            self.send_header('Content-Length', str(clen))

        route_cors = self._cmd and self._cmd.cors_origins and self.command != 'OPTIONS'
        if route_cors:
            # Emit per request. A handler may reuse a response across origins.
            self.send_header('Vary', 'Origin')
            origin = self._allowed_origin(self._cmd)
            if origin:
                self.send_header('Access-Control-Allow-Origin', origin)

        for header, value in response.header_items():
            if route_cors and header.lower() in ('access-control-allow-origin', 'access-control-allow-credentials'):
                continue
            if header.lower() not in tuple(h.lower() for h in _END_EXC_HEADERS):
                self.send_header(header, value)

        self.end_headers()

        if clen and response.is_send_body() and self.command != 'HEAD':
            self.wfile.write(ensure_binary(data))

    def _mk_error_explain_data(self, code, message, explain, charset):
        return ensure_text(self.error_message_format % {'code':    code,
                                                        'message': message,
                                                        'explain': explain},
                           charset)

    def send_error_explain(self, code, message=None, headers=None, content_type=None):
        "do not use directly"
        if headers is None:
            headers = {}

        if code in self.responses:
            if message is None:
                message = self.responses[code][0]

            explain = self.responses[code][1]
        else:
            explain = ""

        if message is None:
            message = ""

        if not isinstance(headers, dict):
            headers = {}

        if not content_type:
            if self._cmd and self._cmd.content_type:
                content_type = self._cmd.content_type
            else:
                content_type = self._DEFAULT_CONTENT_TYPE

        if self._cmd and self._cmd.charset:
            charset = self._cmd.charset
        else:
            charset = DEFAULT_CHARSET

        headers['Content-type'] = "%s; charset=%s" % (content_type, charset)

        data = self._mk_error_explain_data(code, message, explain, charset)

        self.end_response(self.build_response(code, data, headers))

    def send_error_msgtxt(self, code, message, headers=None):
        "text will be in a <pre> bloc"
        if headers is None:
            headers = {}

        if isinstance(message, (list, tuple)):
            message = ''.join(message)
        elif isinstance(message, dict):
            message = repr(message)

        self.send_error_explain(code,
                                ''.join(("<pre>\n", html_escape(message, True), "</pre>\n")), # pylint: disable=deprecated-method
                                headers,
                                "text/html")

    def send_exception(self, code, exc_info=None, headers=None):
        """Keep the public status and headers while withholding exception details."""
        LOG.error('HTTP request failed with status %s', code)
        reason = self.responses.get(code, ('Request failed', ''))[0]
        self.send_error_msg(code, reason, headers)

    def send_error_json(self, code, message, headers=None):
        "send an error to the client. text message is formatted in a json stream"
        if headers is None:
            headers = {}

        self.end_response(HttpResponseJson(code,
                                           {'code':    code,
                                            'message': message},
                                           headers))

    def static_file(self, urlpath, response=None):
        root        = os.path.realpath(self._cmd.root).rstrip(os.sep) + os.sep
        res         = HttpResponse()
        mimetype    = None
        disposition = None

        if isinstance(self._cmd.name, RePatternType) and self._cmd.replacement: # pylint: disable=protected-access
            filename = self._cmd.name.sub(self._cmd.replacement, urlpath)
        else:
            filename = urlpath

        filename    = os.path.realpath(os.path.join(root, filename.strip('/\\')))

        if not filename.startswith(root):
            raise self.req_error(403, "Access denied.")
        if not os.path.exists(filename) or not os.path.isfile(filename):
            raise self.req_error(404, "File does not exist.")
        if not os.access(filename, os.R_OK):
            raise self.req_error(403, "You do not have permission to access this file.")

        if self._cmd.content_type:
            mimetype    = self._cmd.content_type

        if isinstance(response, HttpResponse):
            res         = response
            if not mimetype:
                mimetype    = res.get_header('Content-type')
            disposition = res.get_header('Content-disposition')

        if not mimetype or mimetype == '__MAGIC__':
            try:
                mime     = magic.open(magic.MAGIC_MIME_TYPE)
                mime.load()
                mimetype = mime.file(filename)
            except AttributeError:
                mimetype = magic.from_file(filename, mime = True)

            if mimetype == 'image/svg':
                mimetype += '+xml'
            if mimetype:
                res.add_header('Content-type', mimetype)
        else:
            mimetype    = mimetype.lower()
            if mimetype.startswith('text/') \
               and self._cmd.charset \
               and mimetype.find('charset') == -1:
                res.add_header('Content-type', "%s; charset=%s" % (mimetype, self._cmd.charset))
            else:
                res.add_header('Content-type', mimetype)

        if disposition:
            attachment  = parse_headers(disposition)
            if attachment.disposition == 'attachment' \
               and not attachment.filename_unsafe:
                res.add_header('Content-disposition',
                               build_header(os.path.basename(filename)))

        stats       = os.stat(filename)
        res.add_header('Last-Modified',
                       time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stats.st_mtime)))

        if_modified = self.headers.get('If-Modified-Since')
        if if_modified:
            if_modified = self.parse_date(if_modified.split(';')[0].strip())
            if if_modified is not None and if_modified >= int(stats.st_mtime):
                return res.set_code(304).set_send_body(False)

        f           = None
        body        = binary_type()

        if self.command != 'HEAD':
            with open(filename, 'rb') as f:
                body = f.read()
            if f:
                f.close()

        return res.set_code(200).add_data(body)

    @staticmethod
    def querylist_to_dict(query):
        if not isinstance(query, (list, tuple)):
            return None

        if len(query) > MAX_QUERY_FIELDS:
            raise HttpReqError(414, 'Too many query fields')
        ret = {}
        next_indices = {}

        for x in query:
            if not x:
                continue

            if len(x) > 1:
                value = x[1]
            else:
                value = None

            if not x[0] or x[0].find(']') == -1:
                ret[x[0]] = value
                continue

            lbracket    = x[0].find('[')

            if lbracket == -1:
                ret[x[0]] = value
                continue

            key         = x[0][:lbracket]

            if key not in ret:
                ret[key] = {}

            matched     = _QUERY_BRACKETS.findall(x[0], lbracket, x[0].rfind(']') + 1)
            nb          = len(matched)

            if nb > MAX_QUERY_DEPTH:
                raise HttpReqError(414, 'Query nesting exceeds limit')
            if nb == 0:
                ret[key] = value
                continue

            if not isinstance(ret[key], dict):
                ret[key] = {}

            ref         = ret[key]
            j           = 0

            for i, k in enumerate(matched):
                if k == '':
                    # Literal indices are strings. Only [] can allocate integer
                    # keys. Retain the owner to prevent id reuse after a later
                    # field replaces a dictionary with a scalar.
                    entry = next_indices.get(id(ref))
                    if entry is not None:
                        j = max(j, entry[1])
                    next_indices[id(ref)] = (ref, j + 1)
                    k = j

                if i == (nb - 1):
                    ref[k] = value
                elif k not in ref \
                or (nb > i and not isinstance(ref[k], dict)):
                    ref[k] = {}

                ref = ref[k]

        if '____ts' in ret:
            del ret['____ts']

        return ret

    def _pathify(self):
        """
        rfc2616 says in 5.1.2: "all HTTP/1.1 servers MUST accept the
        absoluteURI form in requests" so if we get one, transform it
        to abs_path.
        Raises HttpReqError if the request is malformed, else returns
        (path, query, fragment)
        """
        try:
            path = self.path
            if helpers.has_len(path):
                path = re.sub(r'^/+', '/', path)

            # Bound field splitting and percent decoding in urisup as well.
            target = path.partition('#')[0]
            query_start = target.find('?')
            if query_start >= 0 and target.count('&', query_start) >= MAX_QUERY_FIELDS:
                raise self.req_error(414, 'Too many query fields')

            (path,
             query,
             self._fragment) = urisup.uri_help_split(path)[2:]

            if not path:
                path = '/'

            if path[0] != '/':
                raise urisup.InvalidURIError('path %r does not start with "/"' % path)

            self._path = re.sub(r'/+', '/', path)

            if query:
                try:
                    self._query_params = self.querylist_to_dict(query)
                except HttpReqError as error:
                    raise self.req_error(error.code, error.text)

            return self._path
        except urisup.InvalidURIError:
            LOG.error("invalid request URI")
            raise self.req_error(400, "Invalid request URI")

    def authenticate(self, auth_users = None):
        context = self.get_context()
        auth_context = context.auth
        for x in ('HTTP_AUTH_USER', 'HTTP_AUTH_PASSWD', 'HTTP_AUTH_IDENTITY'):
            self._SERVER.pop(x, None)

        if context.auth_provider is not None:
            self._authenticate_provider(context.auth_provider, auth_users)
            return

        if not auth_context:
            raise self.req_error(401, 'Authentication is not configured')

        auth    = self.headers.get('Authorization')
        if not auth:
            raise auth_context.unauthorized()

        if not auth_context.valid_authorization(auth) or auth_context.user is None:
            raise auth_context.unauthorized()
        if auth_users and auth_context.user not in auth_users:
            raise auth_context.unauthorized()
        self._SERVER['HTTP_AUTH_USER'] = auth_context.user

    def _authenticate_provider(self, provider, auth_users):
        headers = tuple((key.lower(), value) for key, value in self.headers.items()
                        if key.lower() in AUTH_HEADER_NAMES)
        request = AuthenticationRequest(self.command, self._path, headers, self.client_address[0])
        challenge = self.get_context().auth_challenge
        response_headers = {'WWW-Authenticate': challenge} if challenge else {}
        try:
            # Reject ambiguous security headers before delegating to a provider.
            for name in AUTH_HEADER_NAMES:
                request.header(name)
            identity = provider.authenticate(request)
            if identity is None:
                raise AuthenticationDenied()
            if not isinstance(identity, Identity):
                raise AuthenticationUnavailable()
        except AuthenticationDenied:
            raise self.req_error(401, 'Authentication required', headers=response_headers)
        except Exception:
            # Backend exception text may contain credentials or connection secrets.
            LOG.error('Authentication provider failed')
            raise self.req_error(503, 'Authentication unavailable')
        if auth_users and identity.principal not in auth_users:
            raise self.req_error(403, 'Access denied')
        self._SERVER['HTTP_AUTH_USER'] = identity.principal
        self._SERVER['HTTP_AUTH_IDENTITY'] = identity

    def set_cookie(self, name, value = '', expires = 0, path = '/', domain = '', secure = False, http_only = False):
        cook                   = http_cookies.SimpleCookie()
        cook[name]             = value
        cook[name]['expires']  = expires
        cook[name]['path']     = path
        cook[name]['domain']   = domain
        cook[name]['secure']   = secure
        cook[name]['httponly'] = http_only

        self.send_header('Set-Cookie', cook.output(header = ''))

    def read_cookies(self):
        if 'cookie' in self.headers:
            return http_cookies.SimpleCookie(self.headers['cookie'])

        return None

    @staticmethod
    def parse_payload(data, charset):
        return urlparse.parse_qsl(ensure_text(data, encoding = charset))

    @staticmethod
    def response_dumps(data, charset): # pylint: disable=unused-argument
        if isinstance(data, bool):
            data = int(data)

        if data is None:
            return ""

        if helpers.is_scalar(data):
            return "%s" % data

        if hasattr(data, '__str__') \
           and type(data).__str__ is not object.__str__:
            return "%s" % data

        return repr(data)

    def _resolve_command(self, method, cmd):
        context = self.get_context()
        if not isinstance(self._query_params, dict):
            self._query_params = {}
        named = context.named_commands.get('%s /%s' % (method, cmd))
        if named is not None:
            return named
        for key in sorted(context.regex_commands, key=len, reverse=True):
            if key.startswith(method + ' '):
                command = context.regex_commands[key]
                match = command.name.match(cmd)
                if match:
                    self._query_params.update(match.groupdict())
                    return command
        return None

    def _missing_command(self, cmd):
        """Distinguish an unknown path from an unsupported registered method."""
        context = self.get_context()
        allowed = set()
        for key in context.named_commands:
            method, path = key.split(' ', 1)
            if path == '/' + cmd:
                allowed.add(method)
        for key, command in context.regex_commands.items():
            if command.name.match(cmd):
                allowed.add(key.split(' ', 1)[0])
        if allowed:
            return self.req_error(405, 'Method not allowed',
                                  headers={'Allow': ', '.join(sorted(allowed))})
        return self.req_error(404)

    def data_from_query(self, cmd):
        """
        Callback for .execute_command() for DELETE/GET/HEAD requests
        """
        res  = None
        self._cmd = self._resolve_command(self.command, cmd)

        try:
            if not self._cmd:
                raise self._missing_command(cmd)

            charset = self._cmd.charset or DEFAULT_CHARSET

            if not self._cmd.to_log:
                self._to_log = False

            if self._cmd.to_auth:
                self.authenticate(self._cmd.auth_users)

            if self._cmd.static:
                if self._cmd.handler:
                    res = self._cmd.handler(self)

                return self.static_file(cmd, res)

            res = self._cmd.handler(self)

            if not isinstance(res, HttpResponse):
                return self.response_dumps(res, charset)

            return res
        finally:
            self._query_params = {}

    def _header_values(self, name):
        get_all = getattr(self.headers, 'get_all', None) or getattr(self.headers, 'getheaders', None)
        if get_all is not None:
            return get_all(name) or []
        return [self.headers[name]] if name in self.headers else []

    def _allowed_origin(self, command):
        origins = self._header_values('Origin')
        if len(origins) == 1 and origins[0] in command.cors_origins:
            return origins[0]
        return None

    def _validate_request_framing(self):
        """Reject ambiguous framing before authentication or application code."""
        lengths = self._header_values('Content-Length')
        encodings = self._header_values('Transfer-Encoding')
        self.close_connection = True
        if encodings and lengths:
            raise self.req_error(400, 'Conflicting request framing')
        if len(encodings) > 1:
            raise self.req_error(400, 'Multiple Transfer-Encoding headers')
        if encodings and encodings[0].strip().lower() != 'identity':
            raise self.req_error(400, 'Unsupported Transfer-Encoding')
        values = []
        for header in lengths:
            for value in header.split(','):
                value = value.strip(' \t')
                if not _CONTENT_LENGTH.match(value):
                    raise self.req_error(400, 'Invalid Content-Length')
                try:
                    values.append(int(value))
                except ValueError:
                    raise self.req_error(400, 'Invalid Content-Length')
        if values and any(value != values[0] for value in values):
            raise self.req_error(400, 'Conflicting Content-Length headers')
        return values[0] if values else 0

    def _read_body(self, length):
        if self._deadline_input is None:
            return self.rfile.read(length)
        budget = min(self.body_max_seconds,
                     self.body_grace_seconds + float(length) / self.body_bytes_per_second)
        self._deadline_input.deadline = monotonic() + budget
        try:
            return self.rfile.read(length)
        except socket.timeout:
            self.close_connection = True
            raise self.req_error(408, 'Request body read deadline exceeded')
        finally:
            self._deadline_input.deadline = None

    def data_from_payload(self, cmd):
        """
        Callback for .execute_command() for PATCH/POST/PUT requests
        """
        context = self.get_context()
        multipart = False
        self._cmd = self._resolve_command(self.command, cmd)

        try:
            if not self._cmd:
                raise self._missing_command(cmd)

            charset  = self._cmd.charset or DEFAULT_CHARSET

            clen = self._validate_request_framing()

            ctype    = self.headers.get('Content-Type')
            if ctype:
                ctype = ctype.lower().split(';', 1)[0]
                if ctype == 'multipart/form-data':
                    if not self._ALLOWED_MULTIPART_FORM:
                        raise self.req_error(415, "Unsupported Content-Type")
                    multipart = True
                elif self._ALLOWED_CONTENT_TYPES:
                    ct_found = False
                    for x in self._ALLOWED_CONTENT_TYPES:
                        if ctype == x:
                            ct_found = True
                            break
                    if not ct_found:
                        raise self.req_error(415, "Unsupported Content-Type")

            max_body_size = self._cmd.max_body_size
            if max_body_size is None:
                max_body_size = int(context.options['max_body_size'])

            if clen > max_body_size:
                raise self.req_error(413)

            if self._cmd.to_auth:
                self.authenticate(self._cmd.auth_users)

            if clen > 0:
                payload = self._read_body(clen)
                if len(payload) != clen:
                    raise self.req_error(400, 'Incomplete request body')
                self._payload = BytesIO(payload)

                if multipart:
                    try:
                        self._payload_params = cgi.FieldStorage(environ = {'REQUEST_METHOD': 'POST'},
                                                                fp      = self._payload,
                                                                headers = self.headers)
                    except Exception:
                        raise self.req_error(400, "Invalid request body")
                else:
                    try:
                        if ctype == 'application/x-www-form-urlencoded':
                            self._payload_params = urlparse.parse_qsl(ensure_text(payload,
                                                                                  encoding = charset))
                        else:
                            self._payload_params = self.parse_payload(payload, charset)
                    except ValueError:
                        raise self.req_error(400, "Invalid request body")

            res = self._cmd.handler(self)

            if not isinstance(res, HttpResponse):
                return self.response_dumps(res, charset)

            return res
        finally:
            payload              = None
            self._payload        = None
            self._payload_params = None
            self._query_params   = {}

    def common_req(self, execute, send_body=True):
        "Common code for GET and POST requests"
        self._SERVER         = {'CLIENT_ADDR_HOST': self.client_address[0],
                                'CLIENT_ADDR_PORT': self.client_address[1]}

        self._to_log         = True
        self._cmd            = None

        self._payload        = None
        self._path           = None
        self._payload_params = None
        self._query_params   = {}
        self._fragment       = None

        (cmd, res, req)      = (None, None, None)

        try:
            try:
                self._validate_request_framing()
                path = self._pathify() # pylint: disable-msg=W0612
                cmd  = path[1:]
                res  = execute(cmd)
            except HttpReqError as e:
                e.report(self)
            except Exception:
                try:
                    self.send_error_msg(500, 'Internal server error')
                except Exception: # pylint: disable-msg=W0703
                    pass
                raise
            else:
                if not isinstance(res, HttpResponse):
                    req = self.build_response()
                    req.add_data(res)
                    req.set_send_body(send_body)
                else:
                    req = res

                self.end_response(req)
        except socket.error as e:
            if e.errno in (errno.ECONNRESET, errno.EPIPE):
                return
            LOG.exception("exception - cmd=%r - method=%r", cmd, self.command)
        except Exception: # pylint: disable-msg=W0703
            LOG.exception("exception - cmd=%r - method=%r", cmd, self.command)
        finally:
            del req, res

    def do_DELETE(self):
        "DELETE method"
        self.common_req(self.data_from_query)

    def do_GET(self):
        "GET method"
        self.common_req(self.data_from_query)

    def do_HEAD(self):
        "HEAD method"
        self.common_req(self.data_from_query, send_body=False)

    def do_OPTIONS(self):
        "OPTIONS method"
        self._query_params = {}
        self._cmd = None
        try:
            self._validate_request_framing()
            cmd = self._pathify()[1:]
            methods = self._header_values('Access-Control-Request-Method')
            if not methods:
                raise self._missing_command(cmd)
            if len(methods) != 1 or methods[0] not in _METHODS:
                raise self.req_error(403)
            command = self._resolve_command(methods[0], cmd)
            origin = self._allowed_origin(command) if command is not None else None
            if not origin:
                raise self.req_error(403)
            headers = [name.strip().lower()
                       for line in self._header_values('Access-Control-Request-Headers')
                       for name in line.split(',')]
            if not _CORS_REQUEST_HEADERS.issuperset(headers):
                raise self.req_error(403)
        except HttpReqError as error:
            error.report(self)
            return
        response = self.build_response(code=204)
        response.add_header('Access-Control-Allow-Origin', origin)
        response.add_header('Access-Control-Allow-Methods', methods[0])
        response.add_header('Vary', _CORS_PREFLIGHT_VARY)
        if headers:
            response.add_header('Access-Control-Allow-Headers', ', '.join(sorted(set(headers))))
        self.end_response(response)

    def do_PATCH(self):
        "POST method"
        self.common_req(self.data_from_payload)

    def do_POST(self):
        "POST method"
        self.common_req(self.data_from_payload)

    def do_PUT(self):
        "PUT method"
        self.common_req(self.data_from_payload)



class HttpServerContext(object):
    """Explicit routing, authentication, options and lifecycle for one server.

    Configure/register before run(). Global signal handlers are opt-in because
    signals belong to the process, not to an individual embedded server.
    """
    def __init__(self):
        self.auth = None
        self.auth_provider = None
        self.auth_challenge = None
        self.commands = {}
        self.named_commands = {}
        self.regex_commands = {}
        self.options = DEFAULT_OPTIONS.copy()
        self.server = None
        self.killed = False
        self._running = False
        self._lifecycle_lock = threading.RLock()
        self._startup_cleanup = None

    def _unique_commands(self):
        """Yield each registration once, preserving distinct registrations."""
        seen = set()
        for name, cmd in iteritems(self.commands):
            if id(cmd) not in seen:
                seen.add(id(cmd))
                yield name, cmd

    def register(self, handler,
                 op,
                 safe_init     = None,
                 at_start      = None,
                 name          = None,
                 at_stop       = None,
                 static        = False,
                 root          = None,
                 replacement   = None,
                 charset       = DEFAULT_CHARSET,
                 content_type  = None,
                 to_auth       = False,
                 to_log        = True,
                 max_body_size = None,
                 cors_origins = ()):
        """
        Register a command
        @handler: function to execute when the command is received
        @op: http method(s)
        @safe_init: called by the safe_init() function of this module
        @at_start: called once just before the server starts
        @at_stop: called once just before the server stops
        @name: name of the command (if not name, handler.__name__ is used)
        @static: render static file
        @root: root path
        @replacement: rewrite path when name is regexp
        @charset: charset
        @content_type: content_type
        @to_auth: use basic authentification if True
        @to_log: log request if True
        @cors_origins: explicit origins allowed to read this route from a browser
        @max_body_size: maximum request body bytes; None inherits this context's limit

        prototypes:
            handler(args)
            safe_init(options)
            at_start(options)
            at_stop()
        """
        ref_cmd = self.named_commands
        is_reg  = False

        if isinstance(name, RePatternType): # pylint: disable=protected-access
            key         = name.pattern
            ref_cmd     = self.regex_commands
            is_reg      = True
        elif name:
            key         = name
            replacement = None
        else:
            key         = handler.__name__
            name        = handler.__name__
            replacement = None

        methods = []

        if not isinstance(op, (list, tuple)):
            op = [op.upper()]

        for x in op:
            x = x.upper()
            if x not in _METHODS:
                raise ValueError("unknown HTTP method: %r" % x)

            if static and x not in ('GET', 'HEAD'):
                raise ValueError("Static must be GET, HEAD command")

            methods.append(x)

        if not methods:
            raise ValueError("Missing HTTP method")

        if static and not root:
            raise ValueError("Missing root argument for static")

        cmd = Command(name,
                      handler,
                      methods,
                      safe_init,
                      at_start,
                      at_stop,
                      static,
                      root,
                      replacement,
                      charset,
                      content_type,
                      to_auth,
                      to_log,
                      max_body_size,
                      cors_origins)

        for method in methods:
            if not is_reg:
                mkey = "%s /%s" % (method, key)
            else:
                mkey = "%s %s" % (method, key)

            if mkey in self.commands:
                raise ValueError("%s is already registred" % name)
            self.commands[mkey] = cmd
            ref_cmd[mkey]   = self.commands[mkey]

    def init(self, options, use_sigterm_handler=False):
        """
        Must be called just after registration, before anything else
        """
        with self._lifecycle_lock:
            # pylint: disable-msg=W0613
            if self._running:
                raise RuntimeError('cannot initialize a running HTTP context')

            self.auth = None
            self.auth_provider = None
            self.auth_challenge = None
            self.killed = False
            self._startup_cleanup = None

            self.options = DEFAULT_OPTIONS.copy()
            if isinstance(options, dict):
                self.options.update(options)
            else:
                for optname, optvalue in iteritems(DEFAULT_OPTIONS):
                    if hasattr(options, optname):
                        self.options[optname] = getattr(options, optname)
                    else:
                        self.options[optname] = optvalue

            provider = self.options['auth_provider']
            challenge = getattr(provider, 'challenge', None)
            if provider is not None:
                if not callable(getattr(provider, 'authenticate', None)):
                    raise ValueError('auth_provider must implement authenticate(request)')
                if self.options['auth_basic_file']:
                    raise ValueError('auth_provider and auth_basic_file are mutually exclusive')
                if challenge is not None and (not isinstance(challenge, (str, type(u'')))
                        or not challenge or len(challenge) > 1024
                        or any(ord(char) < 32 or ord(char) > 126 for char in challenge)):
                    raise ValueError('invalid authentication challenge')
            self.auth_provider = provider
            self.auth_challenge = challenge

            if self.options['testmethods']:
                def fortytwo(request):
                    "test GET method"
                    return 42
                def ping(request):
                    "test POST method"
                    return request.payload_params()
                self.register(fortytwo, 'GET')
                self.register(ping, 'POST')

            if self.options['auth_basic_file']:
                self.auth = HttpAuthentication(self.options['auth_basic_file'],
                                           realm=self.options['auth_basic'],
                                           allow_legacy_hashes=self.options['auth_basic_allow_legacy_hashes']).parse_file()

            for name, cmd in self._unique_commands():
                if cmd.safe_init:
                    LOG.info("safe_init: %r", name)
                    cmd.safe_init(self.options)

            if use_sigterm_handler:
                # signal.signal(signal.SIGHUP, lambda *x: None) # XXX
                signal.signal(signal.SIGTERM, self.sigterm_handler)
                signal.signal(signal.SIGINT, self.sigterm_handler)


    def bind_handler(self, handler=HttpReqHandler):
        """Bind without mutating a supplied handler class or another context."""
        class BoundHttpReqHandler(handler):
            _httpdis_context = self
            _ALLOWED_CONTENT_TYPES = list(getattr(handler, '_ALLOWED_CONTENT_TYPES', ()))
        for name in _SERVER_VERSION_OPTIONS:
            if self.options.get(name) is not None:
                setattr(BoundHttpReqHandler, name, self.options[name])
        return BoundHttpReqHandler

    def sigterm_handler(self, signum, stack_frame):
        return self.stop()

    def stop(self):
        with self._lifecycle_lock:
            if self.killed:
                return
            self.killed = True
            server = self.server
        # Application callbacks may wait for workers. Do not hold the lifecycle
        # lock while they run; the serving thread must be able to finish.
        commands = (self._unique_commands() if self._startup_cleanup is None
                    else self._startup_cleanup)
        cleanups = [(name, cmd.at_stop) for name, cmd in commands
                    if cmd.at_stop]
        if server:
            cleanups.extend((('server.kill', server.kill),
                             ('server.server_close', server.server_close)))
        first_error = None
        try:
            for name, cleanup in cleanups:
                try:
                    LOG.info("at_stop: %r", name)
                    cleanup()
                except BaseException:
                    if first_error is None:
                        first_error = sys.exc_info()
                    LOG.error('HTTP shutdown cleanup failed: %r', name)
            if first_error is not None:
                reraise(*first_error)
        finally:
            # Do not retain this frame through the saved exception traceback.
            first_error = None

    def run(self, options=None, http_req_handler=HttpReqHandler,
            http_server_class=HttpListeningServer):
        server = None
        with self._lifecycle_lock:
            if self._running:
                raise RuntimeError('HTTP context is already running')
            if self.killed:
                raise RuntimeError('initialize the HTTP context before restarting')
            self._running = True
        try:
            self._startup_cleanup = [(name, cmd) for name, cmd in self._unique_commands()
                                     if cmd.safe_init]
            with self._lifecycle_lock:
                if self.killed:
                    return
                server = http_server_class(
                    self.options,
                    (self.options['listen_addr'], self.options['listen_port']),
                    self.bind_handler(http_req_handler), name='httpdis')
                self.server = server
                server.httpdis_context = self
            for name, cmd in self._unique_commands():
                if self.killed:
                    break
                if cmd.at_start:
                    if not any(active is cmd for _, active in self._startup_cleanup):
                        self._startup_cleanup.append((name, cmd))
                    LOG.info("at_start: %r", name)
                    cmd.at_start(self.options if options is None else options)
            self._startup_cleanup = None
            LOG.info("will now serve")
            while not self.killed:
                try:
                    server.serve_until_killed()
                except (socket.error, select.error) as why:
                    if errno.EINTR == why.errno:
                        LOG.debug("interrupted system call")
                    elif errno.EBADF == why.errno and self.killed:
                        LOG.debug("server close")
                    else:
                        raise
        except BaseException:
            original_error = sys.exc_info()
            try:
                self.stop()
            except BaseException:
                LOG.exception('HTTP cleanup failed after startup or serving failure')
            reraise(*original_error)
        finally:
            try:
                if server is not None and not self.killed:
                    try:
                        server.kill()
                    finally:
                        server.server_close()
            finally:
                with self._lifecycle_lock:
                    self._running = False
                LOG.info("exiting")


def _legacy_property(name):
    # Retain historical module attributes, including direct reassignment by old
    # consumers and tests, without making independent contexts use them.
    return property(lambda self: globals()[name],
                    lambda self, value: globals().__setitem__(name, value))


class _LegacyHttpServerContext(HttpServerContext):
    auth = _legacy_property('_AUTH')
    commands = _legacy_property('_COMMANDS')
    named_commands = _legacy_property('_NCMD')
    regex_commands = _legacy_property('_RCMD')
    options = _legacy_property('_OPTIONS')
    server = _legacy_property('_HTTP_SERVER')
    killed = _legacy_property('_KILLED')


_DEFAULT_CONTEXT = _LegacyHttpServerContext()


def register(handler,
             op,
             safe_init     = None,
             at_start      = None,
             name          = None,
             at_stop       = None,
             static        = False,
             root          = None,
             replacement   = None,
             charset       = DEFAULT_CHARSET,
             content_type  = None,
             to_auth       = False,
             to_log        = True,
             max_body_size = None,
             cors_origins = ()):
    return _DEFAULT_CONTEXT.register(handler, op, safe_init, at_start, name,
                                     at_stop, static, root, replacement, charset,
                                     content_type, to_auth, to_log, max_body_size, cors_origins)


def sigterm_handler(signum, stack_frame):
    return _DEFAULT_CONTEXT.sigterm_handler(signum, stack_frame)


def stop():
    return _DEFAULT_CONTEXT.stop()


def run(options, http_req_handler=HttpReqHandler,
        http_server_class=HttpListeningServer):
    return _DEFAULT_CONTEXT.run(options, http_req_handler, http_server_class)


def init(options, use_sigterm_handler=True):
    _DEFAULT_CONTEXT.init(options, use_sigterm_handler=False)
    if use_sigterm_handler:
        signal.signal(signal.SIGTERM, sigterm_handler)
        signal.signal(signal.SIGINT, sigterm_handler)
