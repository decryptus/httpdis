# HTTPdis

A small synchronous HTTP dispatcher for Python services: named and regex routes,
JSON/form payloads, responses, static files and Basic authentication.
Used by [dwho](https://github.com/decryptus/dwho), Covenant and Auton.
**HTTPdis is a reference to the TARDIS** in Doctor Who, matching the naming of
Sonicprobe, dwho and Auton. This is independent software, not an official product.

## When to use it

HTTPdis is useful for maintaining and extending services already built around its
request handlers and lifecycle hooks. It uses the Python standard HTTP server and
sonicprobe workers; it is not an ASGI server. For an unrelated new application,
compare the maintenance cost of this custom stack with a maintained web framework.

## Installation

```sh
python -m pip install httpdis
```

The declared range remains Python 2.7 and Python 3.5+. Legacy installations require
compatible dependency versions. On Python 3.13+, `legacy-cgi` and `legacycrypt`
replace removed standard-library APIs while preserving multipart and password-file
interfaces. Static MIME detection requires libmagic. See the CI matrix for actual
tested interpreters and the tests for the covered behaviors.

## Minimal JSON service

```python
from httpdis.ext import httpdis_json as server

def health(request):
    return {'status': 'ok'}

server.register(health, 'GET', name='health')
options = {'listen_addr': '127.0.0.1', 'listen_port': 8080, 'max_workers': 2}
server.init(options)
server.run(options)
```

```sh
curl http://127.0.0.1:8080/health
```

Handlers receive a request with `get_path()`, `query_params()`, `payload_params()`,
`get_headers()` and `get_server_vars()`. They may return data or an `HttpResponse`
/ `HttpResponseJson` to control status and headers. `register` supports method
lists, compiled regular expressions and `safe_init`, `at_start`, `at_stop` hooks.
Routes and options are process-global; use a separate process for independent apps.

## Authentication and deployment

Configure `auth_basic_file` with a trusted htpasswd file and `auth_basic` with the
realm. Set `to_auth=True` on protected routes, or use a username list such as
`to_auth=['alice']`. A protected route without configured authentication now returns
401 rather than allowing the request. Invalid credentials are rejected; request
credentials are isolated between threads. Existing `{SHA}` and system crypt hashes
remain readable for compatibility; legacy SHA-1/DES hashes are not recommendations
for new password storage. Basic credentials require HTTPS in transit.

Bind to loopback or a private interface behind a reverse proxy providing TLS,
request timeouts, connection limits and access controls. This release does not
claim complete HTTP parser hardening for hostile public traffic. Configure
`max_body_size` to limit request bodies. Chunked request bodies are not supported.
Internal exceptions are logged server-side and return a generic 500 to clients.

## Static files

A static route uses `static=True` and `root='/srv/public'`. Regex routes can use
`replacement` to map URLs to filenames. Resolved symlinks outside the root are
rejected. Treat the static directory as administrator-controlled; these checks are
not a filesystem sandbox against concurrent hostile filesystem modifications.
Invalid `If-Modified-Since` values are ignored. Files are buffered in memory, so
serve large downloads through the reverse proxy.

## Compatibility fixes

- Correct UTF-8 response byte lengths and duplicate Content-Type/Length headers.
- Correct Basic authentication on Python 3 and username-list registration.
- Keep credentials isolated across request threads and reject malformed headers.
- Reject missing authentication on protected routes and truncated request bodies.
- Resolve static paths before checking containment; tolerate invalid dates.
- Keep removed CGI/crypt functionality available through compatibility packages.

The dependency loop with sonicprobe is retained because sonicprobe's historical
HTTP JSON module re-exports HTTPdis. A future major release should untangle it.

## Development and publication

```sh
python -m pip install -e . mock
python -m unittest discover -s tests -v
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
```

Update `VERSION`, `RELEASE` and `setup.yml` together. After tests and distribution
validation succeed, the master publication workflow creates `vX.Y.Z` and uploads
via Trusted Publishing (`decryptus/httpdis`, `pypi.yml`, environment `pypi`).
Already-tagged versions are not replaced by ordinary master commits.

License: GPL-3.0-or-later. Original authors and Wazo/Proformatique copyrights are
preserved in the source files.
