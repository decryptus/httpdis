"""Route-specific body limits, including the historical global fallback."""
import json
import re
import threading
import unittest

from six import BytesIO
from six.moves import http_client
from six.moves.BaseHTTPServer import HTTPServer

from httpdis import httpdis as h
from httpdis.ext import httpdis_json


_METHODS = ('POST', 'PUT', 'PATCH')
_INVALID_LIMITS = (-1, True, False, 1.5, float('inf'), float('nan'), '12', [], {})


class BodyLimitTests(unittest.TestCase):
    def setUp(self):
        self.saved = (h._COMMANDS.copy(), h._NCMD.copy(), h._RCMD.copy(), h._OPTIONS, h._AUTH)
        self.addCleanup(self.restore)
        h._COMMANDS.clear()
        h._NCMD.clear()
        h._RCMD.clear()

    def restore(self):
        h._COMMANDS.clear()
        h._COMMANDS.update(self.saved[0])
        h._NCMD.clear()
        h._NCMD.update(self.saved[1])
        h._RCMD.clear()
        h._RCMD.update(self.saved[2])
        h._OPTIONS, h._AUTH = self.saved[3:]

    def test_invalid_limits_fail_before_any_route_is_registered(self):
        for value in _INVALID_LIMITS:
            with self.assertRaises(ValueError):
                h.register(lambda request: None, _METHODS, name='invalid', max_body_size=value)
            self.assertEqual(h._COMMANDS, {})
            self.assertEqual(h._NCMD, {})
            self.assertEqual(h._RCMD, {})

    def test_old_positional_command_constructor_inherits_global_limit(self):
        command = h.Command('legacy', None, _METHODS, None, None, None, False,
                            None, None, 'utf-8', None, False, True)
        self.assertIsNone(command.max_body_size)
        h.register(lambda request: None, 'POST', None, None, 'legacy', None,
                   False, None, None, 'utf-8', None, False, False)
        self.assertIsNone(h._COMMANDS['POST /legacy'].max_body_size)
        self.assertFalse(h._COMMANDS['POST /legacy'].to_log)

    def test_oversized_body_is_rejected_before_read_parse_or_handler(self):
        calls = []
        h.register(lambda request: calls.append('handler'), 'POST', name='small', max_body_size=3)
        h.init({'max_body_size': 100}, use_sigterm_handler=False)

        class Handler(h.HttpReqHandler):
            def __init__(self):
                pass

            @staticmethod
            def parse_payload(data, charset):
                calls.append('parse')
                return data

        handler = Handler()
        handler.command = 'POST'
        handler.headers = {'Content-Length': '4', 'Content-Type': 'application/json'}
        handler.rfile = BytesIO(b'null')
        handler._cmd = None
        with self.assertRaises(h.HttpReqError) as error:
            handler.data_from_payload('small')
        self.assertEqual(error.exception.code, 413)
        self.assertEqual(handler.rfile.tell(), 0)
        self.assertEqual(calls, [])
        self.assertEqual(h._OPTIONS['max_body_size'], 100)

    def test_real_requests_use_named_regex_and_global_limits_for_all_body_methods(self):
        echo = lambda request: request.payload_params()
        httpdis_json.register(echo, _METHODS, name='small', max_body_size=4)
        httpdis_json.register(echo, _METHODS, name=re.compile(r'^large/(?P<id>[0-9]+)$'), max_body_size=16)
        httpdis_json.register(echo, _METHODS, name='default')
        httpdis_json.register(echo, _METHODS, name='explicit-default', max_body_size=None)
        httpdis_json.register(echo, _METHODS, name='empty', max_body_size=0)
        # Routes are registered before init; None must inherit the runtime limit.
        h.init({'max_body_size': 8}, use_sigterm_handler=False)
        server = HTTPServer(('127.0.0.1', 0), httpdis_json.HttpReqHandler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        thread.daemon = True
        thread.start()
        try:
            def request(method, path, body):
                connection = http_client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                try:
                    connection.request(method, path, body, {'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            for method in _METHODS:
                self.assertEqual(request(method, '/small', b'null')[0], 200)
                self.assertEqual(request(method, '/small', b'null ')[0], 413)
                for path in ('/default', '/explicit-default'):
                    self.assertEqual(request(method, path, b'null    ')[0], 200)
                    self.assertEqual(request(method, path, b'null     ')[0], 413)
                self.assertEqual(request(method, '/large/12', b'null' + b' ' * 12)[0], 200)
                self.assertEqual(request(method, '/large/12', b'null' + b' ' * 13)[0], 413)
                self.assertEqual(request(method, '/empty', b'')[0], 200)
                self.assertEqual(request(method, '/empty', b'0')[0], 413)
                # Limits count UTF-8 bytes, not Unicode characters (3 vs 5).
                self.assertEqual(request(method, '/small', b'"\xe2\x82\xac"')[0], 413)
                status, body = request(method, '/large/12', b'"\xe2\x82\xac"')
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body.decode('utf-8')), u'\u20ac')
            self.assertEqual(h._OPTIONS['max_body_size'], 8)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
