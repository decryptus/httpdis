# -*- coding: utf-8 -*-
import socket
import threading
import unittest
from collections import OrderedDict
from six.moves.BaseHTTPServer import HTTPServer
from six.moves.socketserver import ThreadingMixIn
try:
    from unittest import mock
except ImportError:
    import mock
from httpdis import httpdis as h
from httpdis.ext import httpdis_json as j
from httpdis.content_disposition import build_header, parse_headers


class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class FramingAuditTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.auth = [], []
        context = j.HttpServerContext()
        context.register(lambda r: self.calls.append(r.payload_params()) or {'ok': True}, 'POST', name='echo', to_auth=True)
        context.register(lambda r: 'hello', ['GET', 'HEAD'], name='text')
        context.register(lambda r: h.HttpResponse(data=u'caf\u00e9'), ['GET', 'HEAD'], name='raw')
        for code in (204, 205, 304):
            context.register(lambda r, status=code: h.HttpResponse(data='hidden', code=status), 'GET', name=str(code))
        context.init({})
        base = context.bind_handler()
        auth = self.auth
        class Handler(base):
            def authenticate(self, users=None):
                auth.append(True)
        self.server = _Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def request(self, headers, method='POST', path='echo', body=b'{}'):
        raw = ('%s /%s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n%s\r\n\r\n' % (method, path, headers)).encode('ascii') + body
        sock = socket.create_connection(self.server.server_address, timeout=2)
        try:
            sock.sendall(raw); sock.shutdown(socket.SHUT_WR)
            parts = []
            while True:
                part = sock.recv(65536)
                if not part: break
                parts.append(part)
            return b''.join(parts)
        finally:
            sock.close()

    def test_ambiguous_and_invalid_lengths_fail_before_authentication(self):
        for headers in ('Content-Length: 2\r\nContent-Length: 10',
                        'Content-Length: 2,10', 'Content-Length: +2', 'Content-Length: -1',
                        'Content-Length: 2x', 'Content-Length:', 'Content-Length: 2,',
                        'Transfer-Encoding: identity\r\nContent-Length: 2',
                        'Transfer-Encoding: chunked\r\nContent-Length: 2',
                        'Transfer-Encoding: identity\r\nTransfer-Encoding: chunked'):
            response = self.request(headers)
            self.assertIn(b' 400 ', response.split(b'\r\n')[0], headers)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.auth, [])

    def test_identical_lengths_are_accepted_and_unsupported_coding_rejected(self):
        for headers in ('Content-Length: 2', 'Content-Length: 2\r\nContent-Length: 2', 'Content-Length: 2, 2'):
            self.assertIn(b' 200 ', self.request(headers).split(b'\r\n')[0])
        self.assertEqual(self.calls, [{}, {}, {}])
        self.assertIn(b' 400 ', self.request('Transfer-Encoding: chunked').split(b'\r\n')[0])
        self.assertEqual(len(self.auth), 3)

    def test_get_and_options_reject_ambiguous_framing(self):
        for method in ('GET', 'HEAD', 'OPTIONS'):
            result = self.request('Content-Length: 2\r\nContent-Length: 3', method, 'text')
            self.assertIn(b' 400 ', result.split(b'\r\n')[0])

    def test_head_reports_get_length_without_body(self):
        get = self.request('', 'GET', 'text', b'')
        head = self.request('', 'HEAD', 'text', b'')
        self.assertIn(b'Content-Length: 7\r\n', get)
        self.assertIn(b'Content-Length: 7\r\n', head)
        self.assertEqual(head.split(b'\r\n\r\n', 1)[1], b'')
        raw = self.request('', 'HEAD', 'raw', b'')
        self.assertIn(b'Content-Length: 5\r\n', raw)
        self.assertEqual(raw.split(b'\r\n\r\n', 1)[1], b'')

    def test_no_content_responses_do_not_send_forbidden_lengths_or_bodies(self):
        for code in (204, 205, 304):
            result = self.request('', 'GET', str(code), b'')
            headers, body = result.split(b'\r\n\r\n', 1)
            self.assertEqual(body, b'')
            if code == 205:
                self.assertIn(b'Content-Length: 0', headers)
            else:
                self.assertNotIn(b'Content-Length:', headers)


class LifecycleAuditTests(unittest.TestCase):
    def test_server_creation_failure_cleans_initialized_resources(self):
        ctx, events = h.HttpServerContext(), []
        ctx.register(lambda r: None, ['GET', 'POST'], name='one',
                     safe_init=lambda o: events.append('init'), at_stop=lambda: events.append('stop'))
        ctx.init({})
        def fail(*args, **kwargs):
            raise OSError('bind failed')
        with self.assertRaises(OSError):
            ctx.run(http_server_class=fail)
        self.assertEqual(events, ['init', 'stop'])
        self.assertFalse(ctx._running)

    def test_each_registration_runs_once_even_when_callbacks_are_shared(self):
        ctx, events = h.HttpServerContext(), []
        init = lambda o: events.append('init')
        start = lambda o: events.append('start')
        stop = lambda: events.append('stop')
        for name in ('first', 'second'):
            ctx.register(lambda r: None, ['GET', 'POST'], name=name, safe_init=init, at_start=start, at_stop=stop)
        ctx.init({})
        server = mock.Mock()
        server.serve_until_killed.side_effect = ctx.stop
        ctx.run(http_server_class=lambda *a, **k: server)
        ctx.stop()
        self.assertEqual(events, ['init', 'init', 'start', 'start', 'stop', 'stop'])
        server.server_close.assert_called_once_with()

    def test_failed_start_cleans_only_entered_phases_and_preserves_original_error(self):
        ctx, events = h.HttpServerContext(), []
        original = ValueError('start failed')
        def start_fail(options):
            events.append('start-fail'); raise original
        def cleanup_fail():
            events.append('cleanup-fail'); raise RuntimeError('cleanup failed')
        ctx.register(lambda r: None, ['GET', 'POST'], name='one', at_start=lambda o: events.append('start'), at_stop=cleanup_fail)
        ctx.register(lambda r: None, 'GET', name='two', at_start=start_fail, at_stop=lambda: events.append('partial-cleanup'))
        ctx.register(lambda r: None, 'GET', name='three', at_start=lambda o: events.append('not-started'), at_stop=lambda: events.append('not-cleaned'))
        ctx.commands = OrderedDict((name, ctx.commands[name]) for name in ('GET /one', 'POST /one', 'GET /two', 'GET /three'))
        ctx.init({})
        server = mock.Mock()
        with self.assertRaises(ValueError) as caught:
            ctx.run(http_server_class=lambda *a, **k: server)
        self.assertIs(caught.exception, original)
        self.assertEqual(events, ['start', 'start-fail', 'cleanup-fail', 'partial-cleanup'])
        ctx.stop()
        self.assertEqual(events.count('partial-cleanup'), 1)
        server.server_close.assert_called_once_with()
        ctx.init({})
        self.assertFalse(ctx.killed)


class DispositionAuditTests(unittest.TestCase):
    def test_ascii_quotes_unicode_and_bare_attachment(self):
        self.assertIsNone(parse_headers('attachment').filename_unsafe)
        for name in ('plain.txt', 'a"b\\c.txt', u'caf\u00e9.txt'):
            header = build_header(name)
            self.assertEqual(parse_headers(header).disposition, 'attachment')
            # RFC 5987 wins over the ASCII fallback when emitted.
            self.assertEqual(parse_headers(header).filename_unsafe, name)
        self.assertIn("filename*=UTF-8''caf%C3%A9.txt", build_header(u'caf\u00e9.txt'))
        self.assertEqual(parse_headers("attachment; filename*=UTF-8''caf%C3%A9.txt").filename_unsafe, u'caf\u00e9.txt')

    def test_control_characters_cannot_inject_headers(self):
        for value in ('a\r\nInjected: yes', 'a\x00b'):
            with self.assertRaises(ValueError): build_header(value)
            with self.assertRaises(ValueError): parse_headers(value)
