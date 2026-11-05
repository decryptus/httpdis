"""Check preflight enforcement and actual writes using a real Chrome browser."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from playwright.sync_api import sync_playwright

from httpdis import httpdis
from httpdis.ext import httpdis_json


class Frontend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<!doctype html><title>CORS check</title>')


def serve(stack, handler):
    server = HTTPServer(('127.0.0.1', 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(thread.join, 2)
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return 'http://127.0.0.1:%s' % server.server_port


POST_JSON = """async url => {
    try {
        const response = await fetch(url, {
            method: 'POST', credentials: 'omit',
            headers: {'Content-Type': 'application/json'}, body: '{}'
        });
        return response.ok && (await response.json()).written ? 'written' : 'unexpected';
    } catch (error) {
        return error.name;
    }
}"""


def main():
    with ExitStack() as stack:
        allowed = serve(stack, Frontend)
        foreign = serve(stack, Frontend)
        context = httpdis_json.HttpServerContext()
        context.init({})
        calls = []

        def write(request):
            calls.append(request.get_path())
            return {'written': True}

        context.register(write, 'POST', name='shared', cors_origins=[allowed])
        context.register(write, 'POST', name='default')
        context.register(lambda request: httpdis.HttpResponse(
            data='<!doctype html><title>Local frontend</title>',
            headers={'Content-Type': 'text/html'}), 'GET', name='home')
        api = serve(stack, context.bind_handler())
        playwright = stack.enter_context(sync_playwright())
        browser = playwright.chromium.launch(channel='chrome')
        stack.callback(browser.close)
        page = browser.new_page()
        for source, target, expected in (
                (allowed, 'default', 'TypeError'), (foreign, 'shared', 'TypeError'),
                (allowed, 'shared', 'written'), (api + '/home', 'default', 'written')):
            page.goto(source)
            actual = page.evaluate(POST_JSON, api + '/' + target)
            assert actual == expected, (source, target, actual)
        assert calls == ['/shared', '/default'], calls
        print('Verified two denied preflights and two successful browser writes')


if __name__ == '__main__':
    main()
