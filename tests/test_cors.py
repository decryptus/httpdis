"""Exercise route-level browser access on the wire, including handler errors."""
import logging
import re
import threading
import unittest

from six import StringIO
from six.moves import http_client
from six.moves.BaseHTTPServer import HTTPServer
from httpdis import httpdis as h
from httpdis.ext import httpdis_json as j


ORIGIN = 'https://console.example.org'
ROUTE = re.compile(r'^jobs/(?P<id>[0-9]+)$')


class CorsTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.queries = []
        self.shared = h.HttpResponse(data='result', headers={'Vary': 'Accept-Encoding'})
        context = j.HttpServerContext()
        context.init({})
        def callback(request):
            self.queries.append(request.query_params().copy())
            self.calls.append(request.query_params().get('id'))
            return self.shared
        context.register(callback, 'POST', name=ROUTE, cors_origins=[ORIGIN])
        context.register(callback, 'POST', name='jobs/0')
        context.register(callback, 'GET', name='private', to_auth=True, cors_origins=[ORIGIN])
        self.server = HTTPServer(('127.0.0.1', 0), context.bind_handler())
        thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        thread.daemon = True
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, headers):
        connection = http_client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            connection.putrequest(method, path)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            return response
        finally:
            connection.close()

    def test_exact_origin_method_headers_and_named_route_precedence(self):
        base = [('Origin', ORIGIN), ('Access-Control-Request-Method', 'POST')]
        permitted = base + [('Access-Control-Request-Headers', 'Authorization, Content-Type')]
        reply = self.request('OPTIONS', '/jobs/1', permitted)
        self.assertEqual(reply.status, 204)
        self.assertEqual(reply.getheader('Access-Control-Allow-Origin'), ORIGIN)
        self.assertEqual(reply.getheader('Access-Control-Allow-Methods'), 'POST')
        self.assertEqual(reply.getheader('Access-Control-Allow-Headers'), 'authorization, content-type')
        for path, headers in (('/jobs/0', base), ('/missing', base),
                              ('/jobs/1', [('Origin', ORIGIN), ('Access-Control-Request-Method', 'PUT')]),
                              ('/jobs/1', base + [('Access-Control-Request-Headers', 'x-secret')]),
                              ('/jobs/1', base + [('Origin', ORIGIN)]),
                              ('/jobs/1', base + [('Access-Control-Request-Method', 'POST')]),
                              ('/jobs/1', [('Origin', ORIGIN + '.evil'), base[1]])):
            reply = self.request('OPTIONS', path, headers)
            self.assertEqual(reply.status, 403)
            self.assertIsNone(reply.getheader('Access-Control-Allow-Origin'))
        self.assertEqual(self.calls, [])

    def test_access_log_omits_query_and_authority_on_success_and_failure(self):
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        level = h.LOG.level
        h.LOG.addHandler(handler)
        h.LOG.setLevel(logging.DEBUG)
        try:
            cases = (
                ('POST', '/jobs/1?target=http%3A%2F%2Fupstream%2F%3Ftoken%3DPRIVATE_QUERY', 200),
                ('GET', 'http://user:PRIVATE_AUTH@localhost/missing?token=PRIVATE_QUERY', 404),
                ('GET', '/missing?token=PRIVATE_QUERY#PRIVATE_FRAGMENT', 404),
                ('GET', '/missing?x={PRIVATE_INVALID}', 400),
                ('GET', '/private?token=PRIVATE_AUTH', 401),
            )
            for method, path, status in cases:
                self.assertEqual(self.request(method, path, []).status, status)
            self.assertEqual(self.queries[0]['target'], 'http://upstream/?token=PRIVATE_QUERY')
            output = stream.getvalue()
            self.assertNotIn('PRIVATE_', output)
            self.assertIn('POST /jobs/1 HTTP/1.1', output)
            self.assertIn('GET /missing HTTP/1.1', output)
            self.assertIn(' 404 ', output)
        finally:
            h.LOG.removeHandler(handler)
            h.LOG.setLevel(level)

    def test_plain_options_lists_registered_methods(self):
        response = self.request('OPTIONS', '/jobs/1', [])
        self.assertEqual(response.status, 405)
        self.assertEqual(response.getheader('Allow'), 'POST')
        self.assertEqual(self.request('OPTIONS', '/missing', []).status, 404)

    def test_actual_response_is_request_local_and_preserves_authentication(self):
        for origin, expected in ((ORIGIN, ORIGIN), ('null', None), (ORIGIN + '.evil', None)):
            response = self.request('POST', '/jobs/1', [('Origin', origin)])
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader('Access-Control-Allow-Origin'), expected)
            self.assertIsNone(response.getheader('Access-Control-Allow-Credentials'))
            self.assertIn('Accept-Encoding', response.getheader('Vary'))
            self.assertIn('Origin', response.getheader('Vary'))
        denied = self.request('GET', '/private', [('Origin', ORIGIN)])
        self.assertEqual(denied.status, 401)
        self.assertEqual(denied.getheader('Access-Control-Allow-Origin'), ORIGIN)
        self.assertEqual(self.calls, ['1', '1', '1'])
        self.assertIsNone(self.shared.get_header('Access-control-allow-origin'))

    def test_registration_rejects_invalid_origins(self):
        for value in (ORIGIN, ['*'], ['null'], [ORIGIN + '/path'], ['https://user@host']):
            with self.assertRaises(ValueError):
                h.register(lambda r: None, 'GET', name='invalid-cors', cors_origins=value)
