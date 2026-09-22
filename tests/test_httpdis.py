import base64
import hashlib
import os
import shutil
import tempfile
import threading
import unittest
from six import BytesIO
from httpdis import httpdis as h

class HttpTests(unittest.TestCase):
    def handler(self):
        class TestHandler(h.HttpReqHandler):
            def __init__(self):
                pass
        handler = TestHandler()
        handler.command = 'GET'
        handler.wfile = BytesIO()
        handler.headers = {}
        handler._cmd = None
        return handler

    def test_basic_auth_accepts_valid_and_rejects_malformed(self):
        auth = h.HttpAuthentication(None)
        auth.users['alice'] = '{SHA}' + base64.b64encode(hashlib.sha1(b'secret').digest()).decode('ascii')
        self.assertTrue(auth.valid_authorization('Basic ' + base64.b64encode(b'alice:secret').decode('ascii')))
        self.assertEqual(auth.user, 'alice')
        for invalid in ('', 'Basic', 'Bearer abc', 'Basic !!!', 'Basic bm9jb2xvbg==', 'Basic YWxpY2U6YmFk'):
            self.assertFalse(auth.valid_authorization(invalid))
            self.assertIsNone(auth.user)

    def test_credentials_are_thread_local(self):
        auth = h.HttpAuthentication(None)
        auth.users['alice'] = '{SHA}' + base64.b64encode(hashlib.sha1(b'secret').digest()).decode('ascii')
        auth.valid_authorization('Basic YWxpY2U6c2VjcmV0')
        result = []
        thread = threading.Thread(target=lambda: result.append(auth.user))
        thread.start(); thread.join(3)
        self.assertEqual(result, [None])
        self.assertEqual(auth.user, 'alice')

    def test_protected_route_fails_closed_without_configuration(self):
        old = h._AUTH
        h._AUTH = None
        try:
            with self.assertRaises(h.HttpReqError) as error:
                self.handler().authenticate()
            self.assertEqual(error.exception.code, 401)
        finally:
            h._AUTH = old

    def test_allowed_users_registration(self):
        cmd = h.Command('test', None, None, None, None, None, False, None, None,
                        None, None, ['alice', ''], True)
        self.assertEqual(cmd.auth_users, ['alice'])

    def test_response_uses_byte_length_and_single_content_headers(self):
        handler = self.handler()
        headers = []
        handler.send_response = lambda **kwargs: None
        handler.send_header = lambda key, value: headers.append((key.lower(), value))
        handler.end_headers = lambda: None
        handler.end_response(h.HttpResponse(data=u'caf\u00e9', headers={'Content-type': 'text/plain', 'Content-length': '999'}))
        self.assertEqual(handler.wfile.getvalue(), b'caf\xc3\xa9')
        self.assertEqual([value for key, value in headers if key == 'content-length'], ['5'])
        self.assertEqual(len([key for key, value in headers if key == 'content-type']), 1)

    def test_static_files_reject_symlinks_outside_root_and_invalid_dates(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, 'public'))
        with open(os.path.join(root, 'secret'), 'wb') as stream:
            stream.write(b'secret')
        os.symlink(os.path.join(root, 'secret'), os.path.join(root, 'public', 'escape'))
        handler = self.handler()
        handler._cmd = h.Command('test', None, None, None, None, None, True,
                                 os.path.join(root, 'public'), None, 'utf-8', 'text/plain', False, True)
        with self.assertRaises(h.HttpReqError) as error:
            handler.static_file('escape')
        self.assertEqual(error.exception.code, 403)
        with open(os.path.join(root, 'public', 'hello'), 'wb') as stream:
            stream.write(b'hello')
        handler.headers['If-Modified-Since'] = 'not a date'
        self.assertEqual(handler.static_file('hello').data, b'hello')

    def test_form_query_nesting(self):
        self.assertEqual(h.HttpReqHandler.querylist_to_dict([('x[a]', '1'), ('x[b]', '2')]),
                         {'x': {'a': '1', 'b': '2'}})

class HTTPIntegrationTests(unittest.TestCase):
    def test_real_json_requests_and_private_exception_response(self):
        from six.moves import http_client
        from six.moves.BaseHTTPServer import HTTPServer
        from httpdis.ext import httpdis_json
        import json
        old = (h._COMMANDS.copy(), h._NCMD.copy(), h._RCMD.copy(), h._OPTIONS, h._AUTH)
        h._COMMANDS.clear(); h._NCMD.clear(); h._RCMD.clear()
        h.register(lambda request: {'status': u'pr\u00eat'}, 'GET', name='health')
        h.register(lambda request: request.payload_params(), 'POST', name='echo')
        def broken(request):
            raise RuntimeError('private-value-do-not-expose')
        h.register(broken, 'GET', name='broken')
        h.init({'max_body_size': 100}, use_sigterm_handler=False)
        server = HTTPServer(('127.0.0.1', 0), httpdis_json.HttpReqHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            def request(method, path, body=None, headers=None):
                conn = http_client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                try:
                    conn.request(method, path, body, headers or {})
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    conn.close()
            status, data = request('GET', '/health')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data.decode('utf-8')), {'status': u'pr\u00eat'})
            status, data = request('POST', '/echo', '{"hello": 42}', {'Content-Type': 'application/json'})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data.decode('utf-8')), {'hello': 42})
            self.assertEqual(request('POST', '/echo', 'x'*101)[0], 413)
            status, data = request('GET', '/broken')
            self.assertEqual(status, 500)
            self.assertNotIn(b'private-value', data)
        finally:
            server.shutdown(); server.server_close(); thread.join(3)
            h._COMMANDS.clear(); h._COMMANDS.update(old[0])
            h._NCMD.clear(); h._NCMD.update(old[1])
            h._RCMD.clear(); h._RCMD.update(old[2])
            h._OPTIONS, h._AUTH = old[3:]
