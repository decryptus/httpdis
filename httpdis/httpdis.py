# -*- coding: utf-8 -*-
# Copyright 2008-2019 The Wazo Authors
# SPDX-License-Identifier: GPL-3.0-or-later
"""httpsdis.httpsdis"""

# TODO: a configuration option to send the backtraces
# or not to the client in error report

# TODO: locks and implements SIGHUP (by reloading the configuration)

# TODO: add some teardown callbacks?
# maybe two stages:
#   - cb teardown stage 1
#   - wait for tread completion in this module
#   - cb teardown stage 2

# TODO: split backtraces in syslog when they are too long

import email.utils
import errno
import json
import logging
import os
import select
import signal
import socket
import sys
import time
import traceback
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
from crypt import crypt
from hashlib import sha1

from six import BytesIO, binary_type, ensure_binary, ensure_text, iteritems
from six.moves import http_cookies
from six.moves.urllib import parse as urlparse, request as urlrequest
from six.moves.BaseHTTPServer import BaseHTTPRequestHandler # pylint: disable=relative-import

import magic

from sonicprobe import helpers
from sonicprobe.libs import threading_tcp_server, urisup

try:
    from rfc6266_parser import build_header, parse_headers
except ImportError:
    from rfc6266 import build_header, parse_headers


BUFFER_SIZE      = 65536
DEFAULT_CHARSET  = 'utf-8'

LOG              = logging.getLogger('httpdis') # pylint: disable-msg=C0103

_METHODS         = ('HEAD',
                    'GET',
                    'DELETE',
                    'PATCH',
                    'POST',
                    'PUT')

_END_EXC_HEADERS = ('Cache-control',
                    'Connection',
                    'Content-type'
                    'Content-length'
                    'Pragma',
                    'Server')

_AUTH            = None
_COMMANDS        = {}
_NCMD            = {}
_RCMD            = {}
_HTTP_SERVER     = None
_KILLED          = False
_OPTIONS         = {}
DEFAULT_OPTIONS  = {'auth_basic':      None,
                    'auth_basic_file': None,
                    'testmethods':     False,
                    'max_body_size':   1 * 1024 * 1024,
                    'max_workers':     1,
                    'max_requests':    0,
                    'max_life_time':   0,
                    'listen_addr':     None,
                    'listen_port':     None,
                    'server_version':  None,
                    'sys_version':     None}


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
                 to_log):
        self.handler      = handler
        self.name         = name
        self.op           = op
        self.safe_init    = safe_init
        self.at_start     = at_start
        self.at_stop      = at_stop
        self.static       = static
        self.root         = root
        self.replacement  = replacement
        self.charset      = charset
        self.content_type = content_type
        self.to_log       = to_log

        if isinstance(to_auth, (list, tuple)):
            self.auth_users = list(filter(to_auth, helpers.has_len))
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

        getattr(req_handler, "send_error_%s" % self.ctype, 'send_error_msg')(self.code, text, self.headers)


class HttpReqErrJson(HttpReqError):
    def __init__(self, code, text=None, exc=None, headers=None):
        HttpReqError.__init__(self, code, text, exc, headers, ctype = 'json')


HTTP_RESPONSE_CLASS = HttpResponse
HTTP_REQERROR_CLASS = HttpReqError


class HttpAuthentication(object): # pylint: disable=useless-object-inheritance
    def __init__(self, htpasswd, realm=None):
        self.htpasswd = htpasswd
        self.realm    = realm
        self.users    = {}
        self.user     = None
        self.passwd   = None

    def parse_file(self):
        f = None

        try:
            with open(self.htpasswd, 'r') as f:
                for line in f.readlines():
                    tmp = line.strip()
                    if not tmp or tmp.startswith('#') or tmp.find(':') < 1:
                        continue
                    user, passwd = tmp.split(':', 1)
                    if not passwd:
                        continue
                    self.users[user] = passwd
        finally:
            if f:
                f.close()

        return self

    def valid_authorization(self, authorization):
        (kind, data) = authorization.split(' ', 1)

        if kind.strip() != 'Basic':
            return False

        (user, _, passwd) = b64decode(data.rstrip()).partition(':')
        self.user         = user
        self.passwd       = passwd
        secret            = self.users.get(user)

        if not secret:
            return False

        if secret.startswith('{SHA}'):
            xhash = sha1()
            xhash.update(passwd)
            return secret == ("{SHA}%s" % b64encode(xhash.digest()))

        return secret == crypt(passwd, secret[:2])

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


class HttpReqHandler(BaseHTTPRequestHandler):
    """
    Handle one HTTP request
    """

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
        return self.headers.dict

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
        """
        Called by send_response()
        TODO: a configuration option to log or not
            (maybe using logging filters?)
        TODO: discriminate by code and dispatch to various log levels
        """
        LOG.info("%r %s %s", self.requestline, code, size)

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

        if response.is_send_body() \
           and self.command != 'HEAD' \
           and code >= 200 \
           and code not in (204, 304):
            data = response.data or ""
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
        self.send_header('Content-Length', str(clen))

        for header, value in response.header_items():
            if header not in _END_EXC_HEADERS:
                self.send_header(header, value)

        self.end_headers()

        if clen:
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
        "send an error response including a backtrace to the client"
        if headers is None:
            headers = {}

        if not exc_info:
            exc_info = sys.exc_info()

        self.send_error_msg(code,
                            traceback.format_exception(*exc_info),
                            headers)

    def send_error_json(self, code, message, headers=None):
        "send an error to the client. text message is formatted in a json stream"
        if headers is None:
            headers = {}

        self.end_response(HttpResponseJson(code,
                                           {'code':    code,
                                            'message': message},
                                           headers))

    def static_file(self, urlpath, response=None):
        root        = os.path.abspath(self._cmd.root) + os.sep
        res         = HttpResponse()
        mimetype    = None
        disposition = None

        if isinstance(self._cmd.name, RePatternType) and self._cmd.replacement: # pylint: disable=protected-access
            filename = self._cmd.name.sub(self._cmd.replacement, urlpath)
        else:
            filename = urlpath

        filename    = os.path.abspath(os.path.join(root, filename.strip('/\\')))

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
            if if_modified >= int(stats.st_mtime):
                return res.set_code(304).set_send_body(False)

        f           = None
        body        = binary_type()

        if self.command != 'HEAD':
            with open(filename, 'rb') as f:
                while True:
                    buf = f.read(BUFFER_SIZE)
                    if not buf:
                        break
                    body += buf
            if f:
                f.close()

        return res.set_code(200).add_data(body)

    @staticmethod
    def querylist_to_dict(query):
        if not isinstance(query, (list, tuple)):
            return None

        ret = {}

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

            matched     = re.findall(r'\[([^\]]*)\]', x[0][lbracket:])
            nb          = len(matched)

            if nb == 0:
                ret[key] = value
                continue

            if not isinstance(ret[key], dict):
                ret[key] = {}

            ref         = ret[key]
            j           = 0

            for i, k in enumerate(matched):
                if k == '':
                    while j in ref:
                        j += 1
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

            (path,
             query,
             self._fragment) = urisup.uri_help_split(path)[2:]

            if not path:
                path = '/'

            if path[0] != '/':
                raise urisup.InvalidURIError('path %r does not start with "/"' % path)

            self._path = re.sub(r'/+', '/', path)

            if query:
                self._query_params = self.querylist_to_dict(query)

            return self._path
        except urisup.InvalidURIError as e:
            LOG.error("invalid URI: %s", e)
            raise self.req_error(400, str(e))

    def authenticate(self, auth_users = None):
        for x in ('HTTP_AUTH_USER', 'HTTP_AUTH_PASSWD'):
            self._SERVER.pop(x, None)

        if not _AUTH:
            return

        auth    = self.headers.get('Authorization')
        if not auth:
            raise _AUTH.unauthorized()

        allowed = _AUTH.valid_authorization(auth)

        if None in (_AUTH.user, _AUTH.passwd):
            return

        self._SERVER['HTTP_AUTH_USER']   = _AUTH.user
        self._SERVER['HTTP_AUTH_PASSWD'] = _AUTH.passwd

        if auth_users and _AUTH.user not in auth_users:
            raise _AUTH.unauthorized()

        if not allowed:
            raise _AUTH.unauthorized()

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
    def parse_payload(data, charset): # pylint: disable=unused-argument
        return urlparse.parse_qsl(data)

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

    def data_from_query(self, cmd):
        """
        Callback for .execute_command() for DELETE/GET/HEAD requests
        """
        res  = None
        ckey = "%s /%s" % (self.command, cmd)

        if not isinstance(self._query_params, dict):
            self._query_params = {}

        if ckey in _NCMD:
            self._cmd = _NCMD[ckey]
        else:
            for key in sorted(_RCMD, key=len, reverse=True):
                if not key.startswith("%s " % self.command):
                    continue

                m = _RCMD[key].name.match(cmd)
                if m:
                    self._cmd = _RCMD[key]
                    self._query_params.update(m.groupdict())
                    break

        try:
            if not self._cmd:
                raise self.req_error(404)

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

    def data_from_payload(self, cmd):
        """
        Callback for .execute_command() for PATCH/POST/PUT requests
        """
        multipart = False
        ckey      = "%s /%s" % (self.command, cmd)

        if not isinstance(self._query_params, dict):
            self._query_params = {}

        if ckey in _NCMD:
            self._cmd = _NCMD[ckey]
        else:
            for key in sorted(_RCMD, key=len, reverse=True):
                if not key.startswith("%s " % self.command):
                    continue

                m = _RCMD[key].name.match(cmd)
                if m:
                    self._cmd = _RCMD[key]
                    self._query_params.update(m.groupdict())
                    break

        try:
            if not self._cmd:
                raise self.req_error(404)

            charset  = self._cmd.charset or DEFAULT_CHARSET

            tenc     = self.headers.get('Transfer-Encoding')
            if tenc and tenc.lower() != 'identity':
                raise self.req_error(501, "Not supported; Transfer-Encoding: %s" % tenc)

            ctype    = self.headers.get('Content-Type')
            if ctype:
                ctype = ctype.lower().split(';', 1)[0]
                if ctype == 'multipart/form-data':
                    if not self._ALLOWED_MULTIPART_FORM:
                        raise self.req_error(501, "Not supported; Content-Type: %s" % ctype)
                    multipart = True
                elif self._ALLOWED_CONTENT_TYPES:
                    ct_found = False
                    for x in self._ALLOWED_CONTENT_TYPES:
                        if ctype == x:
                            ct_found = True
                            break
                    if not ct_found:
                        raise self.req_error(501, "Not supported; Content-Type: %s" % ctype)

            try:
                clen = int(self.headers.get('Content-Length') or 0)
            except (ValueError, TypeError):
                raise self.req_error(411)

            if clen < 0:
                raise self.req_error(411)

            if clen > int(_OPTIONS['max_body_size']):
                raise self.req_error(413)

            if self._cmd.to_auth:
                self.authenticate(self._cmd.auth_users)

            if clen > 0:
                payload       = self.rfile.read(clen)
                self._payload = BytesIO(payload)

                if multipart:
                    try:
                        self._payload_params = cgi.FieldStorage(environ = {'REQUEST_METHOD': 'POST'},
                                                                fp      = self._payload,
                                                                headers = self.headers)
                    except Exception as e:
                        raise self.req_error(415, text=str(e))
                else:
                    try:
                        if ctype == 'application/x-www-form-urlencoded':
                            self._payload_params = urlparse.parse_qsl(payload)
                        else:
                            self._payload_params = self.parse_payload(payload, charset)
                    except ValueError as e:
                        raise self.req_error(415, text=str(e))

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
                path = self._pathify() # pylint: disable-msg=W0612
                cmd  = path[1:]
                res  = execute(cmd)
            except HttpReqError as e:
                e.report(self)
            except Exception:
                try:
                    self.send_exception(500) # XXX 500
                except Exception: # pylint: disable-msg=W0703
                    pass
                raise
            else:
                if not isinstance(res, HttpResponse):
                    req = self.build_response()
                    if send_body:
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
        req = self.build_response(code = 204)
        req.add_header('Access-Control-Allow-Origin', "*")
        req.add_header('Access-Control-Allow-Methods', "OPTIONS, POST")
        req.add_header('Access-Control-Allow-Headers', "Origin, X-Requested-With, Content-Type, Accept, Authorization")
        req.add_header('Access-Control-Max-Age', 1728000)
        self.end_response(req)

    def do_PATCH(self):
        "POST method"
        self.common_req(self.data_from_payload)

    def do_POST(self):
        "POST method"
        self.common_req(self.data_from_payload)

    def do_PUT(self):
        "PUT method"
        self.common_req(self.data_from_payload)


def register(handler,
             op,
             safe_init    = None,
             at_start     = None,
             name         = None,
             at_stop      = None,
             static       = False,
             root         = None,
             replacement  = None,
             charset      = DEFAULT_CHARSET,
             content_type = None,
             to_auth      = False,
             to_log       = True):
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

    prototypes:
        handler(args)
        safe_init(options)
        at_start(options)
        at_stop()
    """
    ref_cmd = _NCMD
    is_reg  = False

    if isinstance(name, RePatternType): # pylint: disable=protected-access
        key         = name.pattern
        ref_cmd     = _RCMD
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
                  to_log)

    for method in methods:
        if not is_reg:
            mkey = "%s /%s" % (method, key)
        else:
            mkey = "%s %s" % (method, key)

        if mkey in _COMMANDS:
            raise ValueError("%s is already registred" % name)
        _COMMANDS[mkey] = cmd
        ref_cmd[mkey]   = _COMMANDS[mkey]

def sigterm_handler(signum, stack_frame):
    """
    Just tell the server to exit.

    WARNING: There are race conditions, for example with TimeoutSocket.accept.
    We don't care: the user can just rekill the process after like 1 sec. if
    the first kill did not work.
    """
    # pylint: disable-msg=W0613
    global _KILLED

    for name, cmd in iteritems(_COMMANDS):
        if cmd.at_stop:
            LOG.info("at_stop: %r", name)
            cmd.at_stop()

    _KILLED = True

    if _HTTP_SERVER:
        _HTTP_SERVER.kill()
        _HTTP_SERVER.server_close()

def stop():
    sigterm_handler(None, None)

def run(options, http_req_handler = HttpReqHandler):
    """
    Start and execute the server
    """
    # pylint: disable-msg=W0613
    global _HTTP_SERVER

    for x in ('server_version', 'sys_version'):
        if _OPTIONS.get(x) is not None:
            setattr(http_req_handler, x, _OPTIONS[x])

    _HTTP_SERVER = threading_tcp_server.KillableThreadingHTTPServer(
        _OPTIONS,
        (_OPTIONS['listen_addr'], _OPTIONS['listen_port']),
        http_req_handler,
        name = "httpdis")

    for name, cmd in iteritems(_COMMANDS):
        if cmd.at_start:
            LOG.info("at_start: %r", name)
            cmd.at_start(options)

    LOG.info("will now serve")
    while not _KILLED:
        try:
            _HTTP_SERVER.serve_until_killed()
        except (socket.error, select.error) as why:
            if errno.EINTR == why[0]:
                LOG.debug("interrupted system call")
            elif errno.EBADF == why[0] and _KILLED:
                LOG.debug("server close")
            else:
                raise

    LOG.info("exiting")

def get_default_options():
    return DEFAULT_OPTIONS.copy()

def init(options, use_sigterm_handler=True):
    """
    Must be called just after registration, before anything else
    """
    # pylint: disable-msg=W0613
    global _AUTH, _OPTIONS

    if isinstance(options, dict):
        _OPTIONS = DEFAULT_OPTIONS.copy()
        _OPTIONS.update(options)
    else:
        for optname, optvalue in iteritems(DEFAULT_OPTIONS):
            if hasattr(options, optname):
                _OPTIONS[optname] = getattr(options, optname)
            else:
                _OPTIONS[optname] = optvalue

    if _OPTIONS['testmethods']:
        def fortytwo(request):
            "test GET method"
            return 42
        def ping(request):
            "test POST method"
            return request.payload_params()
        register(fortytwo, 'GET')
        register(ping, 'POST')

    if _OPTIONS['auth_basic_file']:
        _AUTH = HttpAuthentication(_OPTIONS['auth_basic_file'],
                                   realm = _OPTIONS['auth_basic']).parse_file()

    for name, cmd in iteritems(_COMMANDS):
        if cmd.safe_init:
            LOG.info("safe_init: %r", name)
            cmd.safe_init(_OPTIONS)

    if use_sigterm_handler:
        # signal.signal(signal.SIGHUP, lambda *x: None) # XXX
        signal.signal(signal.SIGTERM, sigterm_handler)
        signal.signal(signal.SIGINT, sigterm_handler)
