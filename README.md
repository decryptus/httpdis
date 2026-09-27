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

## Request body limits

Since HTTPdis 0.6.28, `register(..., max_body_size=...)` sets the body limit
for a named or regex route. It applies to POST, PUT and PATCH before reading or
parsing the body; oversized requests return HTTP 413.

```python
server.register(action_handler, 'POST', name='v1/actions', max_body_size=1024)
server.register(notification_handler, 'POST', name='v1/notifications',
                max_body_size=64 * 1024)
```

Define your handlers before registering them. The value is a non-negative integer
number of **bytes**. `0` allows only an empty body; `None` or an omitted argument
uses the current global `max_body_size` option (1 MiB by default). A route value
replaces the global default and may be smaller or larger. It does not change other
routes or the global option. Negative values, booleans, floats and strings are
rejected during registration.

Existing registrations and positional arguments remain compatible. JSON services
using `httpdis.ext.httpdis_json.register` share the same option. GET/HEAD/DELETE
continue to use the query handler; this option does not change their behavior.

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

See the [September 2026 code and architecture review](docs/REVIEW.md) (French).


### Independent embedded servers

Use `HttpServerContext` when multiple HTTPdis servers must coexist in one process.
Each context owns its routes, options, authentication object and lifecycle state:

```python
from httpdis.ext.httpdis_json import HttpServerContext

api = HttpServerContext()
api.register(lambda request: {'status': 'ready'}, 'GET', name='health')
api.init({'listen_addr': '127.0.0.1', 'listen_port': 8666,
          'max_body_size': 1048576})
api.run()  # Blocking; another thread or the launcher may call api.stop().
```

`httpdis.httpdis.HttpServerContext` uses the plain HTTP handler;
`httpdis.ext.httpdis_json.HttpServerContext` uses the JSON handler. The registration
arguments and route callbacks match the existing module API. Callbacks can obtain
the owning context through `request.get_context()`. Application services should
still receive explicit decoded values and caller identity, not HTTP requests.

`run(options=None, http_req_handler=..., http_server_class=...)` binds a private
handler subclass, so server version settings and mutable content-type lists do
not modify the supplied handler class or another server. Omitting `options`
passes the context's initialized options to `at_start`; supplying it preserves
the historical callback argument behavior. `context.server` exposes the running
transport (including the actual port when listening on port 0).

For a separately constructed stdlib-compatible HTTP server, use
`context.bind_handler(YourHandler)` or assign `server.httpdis_context = context`
before serving requests. The bound handler carries its context explicitly.

Register routes and initialize before serving. A context rejects concurrent
`run()` calls and reinitialization while running. `stop()` affects only that
context and is idempotent until the next `init()`. A stopped context must be
initialized before restarting. Reinitialization retains registered routes, as
with the historical API. This is not a hot-reconfiguration interface. Hooks still
run per registered method/route entry; sharing application objects in callbacks
is the caller's responsibility. Transport shutdown retains Sonicprobe's existing
worker behavior; it does not forcibly cancel running application callbacks.

Signals remain process-wide. Context initialization does **not** install handlers
unless `use_sigterm_handler=True` is explicitly requested. In an embedded process,
let the launcher choose which contexts to stop.

### Compatibility with the global API

The module-level `register`, `init`, `run`, `stop` and `sigterm_handler` functions
remain available with their existing signatures, including the JSON wrappers.
They delegate to a default context. Historical `_COMMANDS`, `_NCMD`, `_RCMD`,
`_OPTIONS`, `_AUTH`, `_HTTP_SERVER` and `_KILLED` attributes still reflect that
context, including direct reassignment. Handlers used without an explicit context
continue to use this default. Global `init()` still installs signal handlers by
default. These global calls remain a single shared server configuration; use
explicit contexts for independent servers.

Routes, authentication, response formats, route/global body-limit fallback and
lifecycle callback arguments remain compatible. Handler classes are now bound
through a subclass rather than modified in place. Repeated `stop()` calls no
longer repeat shutdown hooks. Startup/serving failures close the created socket,
and shutdown-hook failures still trigger transport cleanup.

The default schema is defined once in `httpdis.config`. Both historical
`DEFAULT_OPTIONS` import paths remain independent dictionaries with the same
initial values; `get_default_options()` returns a fresh dictionary. Mutating an
export is not a way to reconfigure an already initialized context.
