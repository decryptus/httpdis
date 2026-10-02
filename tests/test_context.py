"""Independent real servers plus the historical module facade."""
import base64
import errno
import hashlib
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import unittest

try:
    from unittest import mock
except ImportError:
    import mock
from six.moves import http_client
from httpdis import config
from httpdis import httpdis as h
from httpdis.ext import httpdis_json as j

CONTEXT_ROUTE = re.compile(r'^item/(?P<id>[0-9]+)$')
GLOBAL_NAMES = ('_AUTH', '_OPTIONS', '_HTTP_SERVER', '_KILLED', '_COMMANDS', '_NCMD', '_RCMD')


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.saved = dict((name, getattr(h, name)) for name in GLOBAL_NAMES)
        self.addCleanup(self.restore_globals)
        h._AUTH, h._OPTIONS, h._HTTP_SERVER, h._KILLED = None, {}, None, False
        h._COMMANDS, h._NCMD, h._RCMD = {}, {}, {}
        self.threads = []
        self.errors = []
        self.addCleanup(self.stop_servers)

    def restore_globals(self):
        for name, value in self.saved.items():
            setattr(h, name, value)

    def stop_servers(self):
        for context, thread in self.threads:
            context.stop()
            thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])

    def credentials(self, user):
        path = os.path.join(self.directory, user)
        digest = base64.b64encode(hashlib.sha1(b'secret').digest()).decode('ascii')
        with open(path, 'w') as stream:
            stream.write(user + ':{SHA}' + digest + '\n')
        return path

    def start(self, label, user, limit):
        context = j.HttpServerContext()
        ready = threading.Event()
        hooks = []
        def identity(request):
            return {'label': label, 'user': request.get_server_vars().get('HTTP_AUTH_USER')}
        context.register(identity, 'GET', name='identity', to_auth=True,
                         safe_init=lambda options: hooks.append(('init', options['max_body_size'])),
                         at_start=lambda options: ready.set(),
                         at_stop=lambda: hooks.append(('stop', label)))
        context.register(lambda request: label, 'GET', name=label)
        context.register(lambda request: [label, request.query_params()['id']], 'GET', name=CONTEXT_ROUTE)
        context.register(lambda request: request.payload_params(), 'POST', name='echo')
        context.init({'listen_addr': '127.0.0.1', 'listen_port': 0,
                      'auth_basic_file': self.credentials(user), 'auth_basic': label,
                      'server_version': label, 'sys_version': '', 'max_body_size': limit,
                      'max_workers': 2})
        def run():
            try:
                context.run()
            except Exception as error:
                self.errors.append(error)
                ready.set()
        thread = threading.Thread(target=run)
        thread.daemon = True
        self.threads.append((context, thread))
        thread.start()
        self.assertTrue(ready.wait(3))
        self.assertEqual(self.errors, [])
        return context, thread, hooks

    def request(self, context, path, user=None, method='GET', body=None):
        connection = http_client.HTTPConnection('127.0.0.1', context.server.server_port, timeout=3)
        headers = {'Content-Type': 'application/json'}
        if user:
            headers['Authorization'] = 'Basic ' + base64.b64encode((user + ':secret').encode('ascii')).decode('ascii')
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read(), dict((name.lower(), value) for name, value in response.getheaders())
        finally:
            connection.close()

    def test_two_servers_isolate_routes_auth_options_and_shutdown(self):
        original_version = j.HttpReqHandler.server_version
        left, left_thread, left_hooks = self.start('left', 'alice', 4)
        right, right_thread, right_hooks = self.start('right', 'bob', 16)
        # Changing the legacy singleton must not reconfigure either server.
        h.init({'max_body_size': 1}, use_sigterm_handler=False)
        h.register(lambda request: 'legacy', 'GET', name='legacy')
        h.stop()
        for context, label, user, other in ((left, 'left', 'alice', 'bob'),
                                            (right, 'right', 'bob', 'alice')):
            status, body, headers = self.request(context, '/identity', user)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body.decode('utf-8')), {'label': label, 'user': user})
            self.assertEqual(headers['server'], label)
            status, body, headers = self.request(context, '/identity', other)
            self.assertEqual(status, 401)
            self.assertIn(label, headers['www-authenticate'])
            self.assertEqual(self.request(context, '/identity')[0], 401)
            self.assertEqual(self.request(context, '/legacy')[0], 404)
            self.assertEqual(json.loads(self.request(context, '/item/42')[1].decode('utf-8')), [label, '42'])
        self.assertEqual(self.request(left, '/right')[0], 404)
        self.assertEqual(self.request(right, '/left')[0], 404)
        self.assertEqual(self.request(left, '/echo', method='POST', body=b'null ')[0], 413)
        self.assertEqual(self.request(right, '/echo', method='POST', body=b'null ')[0], 200)
        self.assertEqual(j.HttpReqHandler.server_version, original_version)
        left.stop()
        left.stop()
        left_thread.join(3)
        self.assertFalse(left_thread.is_alive())
        self.assertTrue(right_thread.is_alive())
        self.assertEqual(self.request(right, '/identity', 'bob')[0], 200)
        self.assertEqual(left_hooks, [('init', 4), ('stop', 'left')])
        self.assertEqual(right_hooks, [('init', 16)])
        with self.assertRaises(RuntimeError):
            right.init({'max_body_size': 1})
        with self.assertRaises(RuntimeError):
            right.run()
        self.assertEqual(self.request(right, '/echo', method='POST', body=b'null ')[0], 200)

    def test_simultaneous_authenticated_requests_do_not_mix_principals(self):
        left, _, _ = self.start('left', 'alice', 4)
        right, _, _ = self.start('right', 'bob', 16)
        failures = []
        go = threading.Event()
        def fetch(context, user, label):
            try:
                go.wait(3)
                for _ in range(5):
                    status, body, _ = self.request(context, '/identity', user)
                    if status != 200 or json.loads(body.decode('utf-8')) != {'user': user, 'label': label}:
                        failures.append((status, body))
            except Exception as error:
                failures.append(error)
        threads = [threading.Thread(target=fetch, args=args) for args in
                   ((left, 'alice', 'left'), (right, 'bob', 'right'),
                    (left, 'alice', 'left'), (right, 'bob', 'right'))]
        for thread in threads:
            thread.daemon = True
            thread.start()
        go.set()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    def test_legacy_global_run_still_owns_legacy_routes_and_stop(self):
        ready = threading.Event()
        h.register(lambda request: 'legacy', 'GET', name='legacy', at_start=lambda options: ready.set())
        options = {'listen_addr': '127.0.0.1', 'listen_port': 0}
        h.init(options, use_sigterm_handler=False)
        def run():
            try:
                h.run(options)
            except Exception as error:
                self.errors.append(error)
                ready.set()
        thread = threading.Thread(target=run)
        thread.daemon = True
        self.threads.append((h._DEFAULT_CONTEXT, thread))
        thread.start()
        self.assertTrue(ready.wait(3))
        self.assertEqual(self.errors, [])
        self.assertEqual(self.request(h._DEFAULT_CONTEXT, '/legacy')[:2], (200, b'legacy'))
        self.assertIs(h._HTTP_SERVER, h._DEFAULT_CONTEXT.server)
        h.stop()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(h._KILLED)

    def test_handler_binding_copies_mutable_content_types(self):
        left, right = j.HttpServerContext(), j.HttpServerContext()
        a, b = left.bind_handler(), right.bind_handler()
        a._ALLOWED_CONTENT_TYPES.append('application/example')
        self.assertNotIn('application/example', b._ALLOWED_CONTENT_TYPES)
        self.assertNotIn('application/example', j.HttpReqHandler._ALLOWED_CONTENT_TYPES)
        self.assertIs(a._httpdis_context, left)
        self.assertIs(b._httpdis_context, right)

    def test_default_option_exports_remain_independent(self):
        self.assertEqual(config.DEFAULT_OPTIONS, h.DEFAULT_OPTIONS)
        self.assertIsNot(config.DEFAULT_OPTIONS, h.DEFAULT_OPTIONS)
        a, b = config.get_default_options(), h.get_default_options()
        a['max_body_size'] = 3
        self.assertNotEqual(a, b)
        left, right = h.HttpServerContext(), h.HttpServerContext()
        left.options['max_body_size'] = 5
        self.assertEqual(right.options, b)
        opts = {'max_body_size': 7}
        left.init(opts)
        opts['max_body_size'] = 99
        self.assertEqual(left.options['max_body_size'], 7)

    def test_signal_registration_is_opt_in_for_contexts_and_legacy_default(self):
        with mock.patch.object(h.signal, 'signal') as signal:
            h.HttpServerContext().init({})
            self.assertEqual(signal.call_count, 0)
            h.init({})
            self.assertEqual(signal.call_args_list,
                             [mock.call(h.signal.SIGTERM, h.sigterm_handler),
                              mock.call(h.signal.SIGINT, h.sigterm_handler)])

    def test_start_hook_failure_closes_server_and_allows_reinitialization(self):
        context = h.HttpServerContext()
        def fail(options):
            raise ValueError('start failed')
        context.register(lambda request: 'ok', 'GET', name='test', at_start=fail)
        context.init({'listen_addr': '127.0.0.1', 'listen_port': 0})
        with self.assertRaises(ValueError):
            context.run()
        self.assertFalse(context._running)
        self.assertTrue(context.server.killed())
        with self.assertRaises(socket.error) as caught:
            context.server.socket.getsockname()
        self.assertEqual(caught.exception.errno, errno.EBADF)
        context.init({})

    def test_stop_hook_failure_still_closes_server(self):
        context = h.HttpServerContext()
        def fail():
            raise ValueError('stop failed')
        context.register(lambda request: 'ok', 'GET', name='test', at_stop=fail)
        server = mock.Mock()
        context.server = server
        with self.assertRaises(ValueError):
            context.stop()
        self.assertTrue(context.killed)
        self.assertEqual(server.kill.call_count, 1)
        self.assertEqual(server.server_close.call_count, 1)

    def test_stop_runs_all_cleanup_and_preserves_first_failure(self):
        # Include BaseException: an extension's SystemExit must not bypass cleanup.
        for first_error in (ValueError('first'), SystemExit('first')):
            context = h.HttpServerContext()
            calls = []
            def first():
                calls.append('first')
                context.stop()  # Reentrant stop must not repeat callbacks.
                raise first_error
            def second():
                calls.append('second')
                raise RuntimeError('second')
            def last():
                calls.append('last')
            context.register(lambda request: None, 'GET', name='first', at_stop=first)
            context.register(lambda request: None, 'GET', name='second', at_stop=second)
            context.register(lambda request: None, 'GET', name='last', at_stop=last)
            # Dictionary order is not guaranteed on supported legacy interpreters.
            from collections import OrderedDict
            context.commands = OrderedDict((name, context.commands['GET /' + name])
                                           for name in ('first', 'second', 'last'))
            server = mock.Mock()
            server.kill.side_effect = RuntimeError('kill')
            server.server_close.side_effect = RuntimeError('close')
            context.server = server
            with self.assertRaises(type(first_error)) as caught:
                context.stop()
            self.assertIs(caught.exception, first_error)
            self.assertEqual(calls, ['first', 'second', 'last'])
            context.stop()
            self.assertEqual(calls, ['first', 'second', 'last'])
            self.assertEqual(server.kill.call_count, 1)
            self.assertEqual(server.server_close.call_count, 1)

    def test_transport_failure_still_attempts_close_and_is_propagated(self):
        for failing_method in ('kill', 'server_close'):
            context = h.HttpServerContext()
            server = mock.Mock()
            first_error = RuntimeError(failing_method)
            getattr(server, failing_method).side_effect = first_error
            context.server = server
            with self.assertRaises(RuntimeError) as caught:
                context.stop()
            self.assertIs(caught.exception, first_error)
            context.stop()
            self.assertEqual(server.kill.call_count, 1)
            self.assertEqual(server.server_close.call_count, 1)

    def test_custom_stdlib_handler_class_can_be_bound(self):
        from six.moves.BaseHTTPServer import BaseHTTPRequestHandler
        bound = h.HttpServerContext().bind_handler(BaseHTTPRequestHandler)
        self.assertTrue(issubclass(bound, BaseHTTPRequestHandler))

    def test_transport_context_does_not_import_application_or_cli(self):
        import subprocess
        import sys
        script = '''
import sys
# Python 3.5/3.6's stdlib HTTP server imports argparse for its own launcher.
# Load that transport dependency first; project/application imports stay guarded.
from six.moves.BaseHTTPServer import BaseHTTPRequestHandler
try:
    import builtins
except ImportError:
    import __builtin__ as builtins
original_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in ('dwho', 'auton', 'covenant', 'monit_docker', 'argparse', 'curses'):
        raise AssertionError('application or CLI import: ' + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded
from httpdis.ext.httpdis_json import HttpServerContext
context = HttpServerContext()
context.register(lambda request: 'ok', 'GET', name='health')
context.init({})
assert context.bind_handler()._httpdis_context is context
context.stop()
'''
        process = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        timer = threading.Timer(15, process.kill)
        timer.start()
        try:
            output, error = process.communicate()
            self.assertEqual(process.returncode, 0, error)
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
