"""HTTP errors must preserve routing semantics without reflecting request bodies."""
import io
import re
import unittest
from httpdis import httpdis as h
from httpdis.ext import httpdis_json as j


_METHODS = ('GET', 'POST')
_ITEM_ROUTE = re.compile(r'^items/(?P<item>[^/]+)$')


class ContractErrorsTests(unittest.TestCase):
    def handler(self, method='POST', body=b'{"PRIVATE_BODY":', content_type='application/json'):
        context = h.HttpServerContext()
        context.init({}, use_sigterm_handler=False)
        calls = []
        context.register(lambda request: calls.append('called'), _METHODS, name='resource')
        context.register(lambda request: calls.append('called'), 'GET', name=_ITEM_ROUTE)
        class Handler(j.HttpReqHandler):
            def __init__(self):
                pass
        handler = Handler()
        handler._httpdis_context = context
        handler.command = method
        handler.headers = {'Content-Length': str(len(body)), 'Content-Type': content_type}
        handler.rfile = io.BytesIO(body)
        handler._cmd = None
        handler._query_params = {}
        return handler, calls

    def test_malformed_json_and_utf8_are_400_without_body_reflection(self):
        for body in (b'{"PRIVATE_BODY":', b'\xff'):
            handler, calls = self.handler(body=body)
            with self.assertRaises(h.HttpReqError) as raised:
                handler.data_from_payload('resource')
            self.assertEqual(raised.exception.code, 400)
            self.assertEqual(raised.exception.text, 'Invalid request body')
            self.assertEqual(calls, [])

    def test_unsupported_content_type_is_415_without_reflection(self):
        handler, calls = self.handler(content_type='application/PRIVATE_HEADER')
        with self.assertRaises(h.HttpReqError) as raised:
            handler.data_from_payload('resource')
        self.assertEqual(raised.exception.code, 415)
        self.assertEqual(raised.exception.text, 'Unsupported Content-Type')
        self.assertEqual(handler.rfile.tell(), 0)
        self.assertEqual(calls, [])

    def test_named_and_regex_routes_report_allow_without_calling_handlers(self):
        for path, allowed in (('resource', 'GET, POST'), ('items/123', 'GET')):
            for method in ('DELETE', 'PATCH'):
                handler, calls = self.handler(method=method)
                dispatch = handler.data_from_query if method == 'DELETE' else handler.data_from_payload
                with self.assertRaises(h.HttpReqError) as raised:
                    dispatch(path)
                self.assertEqual(raised.exception.code, 405)
                self.assertEqual(raised.exception.headers, {'Allow': allowed})
                self.assertEqual(handler.rfile.tell(), 0)
                self.assertEqual(calls, [])

    def test_unknown_path_stays_404_without_allow(self):
        handler, calls = self.handler()
        with self.assertRaises(h.HttpReqError) as raised:
            handler.data_from_payload('absent')
        self.assertEqual(raised.exception.code, 404)
        self.assertEqual(raised.exception.headers, {})
        self.assertEqual(calls, [])

    def test_authentication_precedes_body_read_and_parse(self):
        handler, calls = self.handler()
        handler._httpdis_context.named_commands['POST /resource'].to_auth = True
        def denied(*args):
            raise handler.req_error(401)
        handler.authenticate = denied
        with self.assertRaises(h.HttpReqError) as raised:
            handler.data_from_payload('resource')
        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(handler.rfile.tell(), 0)
        self.assertEqual(calls, [])
