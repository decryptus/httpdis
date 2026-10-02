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

## Request error contract

The development branch distinguishes invalid request syntax, unsupported media,
missing routes and unsupported methods:

| Request | Response |
| --- | --- |
| Malformed JSON or invalid text encoding for a supported payload | 400, `Invalid request body` |
| Unsupported `Content-Type`, including disabled multipart | 415, `Unsupported Content-Type` |
| Path with no matching named or regex route | 404 |
| Recognized HTTP method with a matching path registered for other methods | 405 with `Allow` |

`Allow` lists the explicitly registered methods for the matching path in sorted
order. It does not invent HEAD or OPTIONS support. Method rejection does not read
the body or invoke a handler. Completely unsupported HTTP verbs remain the base
server's responsibility. These corrections change the previous 415 (malformed
payload), 501 (unsupported media) and 404 (known path, wrong method) responses;
clients should not depend on those old status mappings.

Payload-parser exceptions use a constant error message instead of reflecting
exception text or request body values. The JSON handler retains JSON errors.
This does not sanitize application-owned error messages or custom logging.

A registered route with `to_auth` enabled authenticates before body reading and
parsing. Routing and header/body-size checks may run before authentication;
unknown routes and wrong methods do not inherit another method's auth policy.
Applications still own operation-level authorization. Public routes are unchanged.

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
and shutdown-hook failures do not skip subsequent hooks or transport cleanup.
Shutdown attempts every registered cleanup and re-raises the first failure with
its traceback, even if later hooks or transport cleanup also fail. Reentrant
and repeated `stop()` calls do not run the hooks again.

The default schema is defined once in `httpdis.config`. Both historical
`DEFAULT_OPTIONS` import paths remain independent dictionaries with the same
initial values; `get_default_options()` returns a fresh dictionary. Mutating an
export is not a way to reconfigure an already initialized context.


## Application-owned authentication providers (development)

The embedding daemon may supply `auth_provider` when initializing a server context.
This is an additive extension, not a new default authentication backend. HTTPdis
neither chooses credential storage nor opens a database for this interface.

```python
from httpdis.authentication import AuthenticationProvider, Identity
from httpdis.ext.httpdis_json import HttpServerContext

class DaemonProvider(AuthenticationProvider):
    challenge = 'Bearer'

    def __init__(self, credential_service):
        self.credentials = credential_service

    def authenticate(self, request):
        # The supplied service verifies expiry/revocation and returns an account.
        account = self.credentials.verify(request.header('authorization'))
        if account is None:
            return None
        return Identity(account.name, 'token', account.scopes)

context = HttpServerContext()
# credential_service is constructed/configured by the embedding application.
# context.init({'auth_provider': DaemonProvider(credential_service), ...})
```

Use the same `auth_provider` option on the existing options object or module-level
`init()` facade when needed. Independent daemons must use independent
`HttpServerContext` instances; the historical module facade remains a singleton.
DWho/application configuration should construct a provider explicitly and pass the
instance. No dynamic backend import, YAML syntax, credential path or default store
is introduced by HTTPdis here.

A provider implements `authenticate(AuthenticationRequest)` and returns an
immutable `Identity(principal, method, scopes)`. It may return `None` or raise
`AuthenticationDenied` for invalid/missing/expired/revoked credentials. Backend
failure, including `AuthenticationUnavailable`, produces a generic HTTP 503;
exception details are not exposed or logged by the adapter. There is no fallback
to Basic or anonymous access after provider failure. A fixed optional `challenge`
sets WWW-Authenticate on HTTP 401. Route user allowlists still apply (HTTP 403).

The request contains the method, parsed path without query parameters, selected
security headers as immutable pairs, and the direct socket peer address. Header
lookup is case-insensitive; duplicate security headers are rejected. Forwarded
identity headers are never trusted or passed through this contract. No HTTP
handler, request body or mutable server context is passed to the provider. Do not
log header values: they contain credentials and cookies. The request repr is redacted.

Successful requests expose `HTTP_AUTH_USER` for existing applications and
`HTTP_AUTH_IDENTITY` for the verified method/scopes. They never expose a password.
**Scopes are data, not automatic authorization:** applications must enforce them
alongside endpoint/owner/maintenance permissions before accepting scoped tokens.
Authentication applies only to routes registered with `to_auth`; this extension
does not silently make public routes private.

Providers and their storage adapters must support concurrent calls. Their lifecycle,
configuration, defaults, persistence, revocation and shutdown belong to the daemon.
Two contexts may use distinct provider instances and stores without sharing state.
Sharing a provider is an explicit application decision. HTTPdis does not cache
provider identities or take ownership of the supplied backend.

### Compatibility and remaining work

Without `auth_provider`, Basic, `auth_basic_file`, `auth_basic`, route allowlists
and the historical API keep their behavior. Configuring both a provider and
`auth_basic_file` is rejected rather than establishing an implicit fallback.
The new contract uses syntax supported by the existing Python compatibility matrix
and adds no required dependency.

The provider contract alone does not supply accounts or credential verification;
the optional local service described below supplies those separately. Browser login
HTTP routes and TOTP enrollment/replay protection remain pending. The contract does
not configure cookies, HTTPS, CSRF or CORS automatically.
Browser sessions must not be exposed until those transport controls and the backend
are implemented and tested together. Existing HTTPdis CORS/OPTIONS behavior is
unchanged by this compatibility-preserving addition.

## Local authentication backend (development, optional)

`httpdis.auth_backend.LocalAuthService` supplies local account, opaque session and
opaque API token behavior behind the provider contract. **The daemon must supply
both a store and a password adapter.** No file path, database, credentials, accounts
or HTTP login routes are created by importing HTTPdis.

```python
from httpdis.auth_backend import LocalAuthService, Argon2Passwords, BearerAuthProvider

# store is selected and constructed by the application, not HTTPdis.
# auth = LocalAuthService(store=store, passwords=Argon2Passwords(), audit=audit)
# context.init({'auth_provider': BearerAuthProvider(auth), ...})
```

Install `httpdis[auth]` on Python 3.10+ to use the optional maintained
`argon2-cffi` adapter. It creates Argon2id password hashes. The core/provider
contract and injected service remain compatible with the legacy interpreter
matrix, without installing that optional dependency there. No weak password
implementation is supplied as a fallback. The password adapter contract is
`hash(password) -> encoded_hash` and `verify(encoded_hash, password) -> bool`;
backend/configuration errors must raise, not return a successful identity.

### Administration and account changes

`provision(principal, password, scopes)` creates or replaces an account. Replacing
an account rotates its revision and invalidates all existing sessions/tokens.
`disable(principal)` disables login and invalidates existing credentials.
`issue_token(principal, scopes, ttl)` requires a scope subset of the enabled
account, an explicit TTL no longer than 30 days, and returns a one-time secret plus
a credential ID for `revoke_token(credential_id)`. These are **trusted administrative
service methods**, not unauthenticated user operations. The embedding application
must authorize any management interface it builds around them.

The service validates identity/scope structure using the provider contract. It
never interprets Auton endpoint names or maintenance permissions. Consumers must
apply the verified scopes to business operations. Newly provisioned passwords
must have at least 12 characters and no more than 1,024 UTF-8 bytes; no password
normalization or silent truncation is performed. Applications may impose stronger
password/enrollment policies before provisioning. Updating Argon2 parameters can
be handled by explicit credential rotation; automatic rehash migration is not
implemented in this first adapter.

### Sessions, tokens and bounded work

`login(principal, password, peer)` returns a session grant with its secret, CSRF
secret, expiry and identity. `authenticate_session(secret, csrf, mutation=True)`
checks the CSRF secret before refreshing idle expiry. Session absolute expiry is
8 hours and idle expiry 30 minutes by default, configurable downward at service
construction. Every request checks the enabled account and its revision.
`logout(secret)` revokes that session. Rotation/revocation does not undo work
already authorized or cancel application jobs.

Secrets use 32 bytes of OS randomness. Only SHA-256 digests of session/token/CSRF
secrets are stored; account passwords use the injected password hasher. Raw secrets
are returned to the caller for delivery, never logged by the service. Grant reprs
are redacted. `BearerAuthProvider` accepts only explicit Authorization Bearer
credentials and checks the token on every protected request; there is no Basic
fallback or implicit cookie/session acceptance.

Login work is bounded to two concurrent password verifications per service instance.
A transactional 60-second fixed window allows 5 attempts per account, 20 per direct
peer, and 100 globally per store. Successful attempts count too. Unknown accounts
still perform dummy password verification after admission. Applications should
also limit login traffic at their trusted ingress; this bounded local policy can
reject legitimate logins during a distributed attack. Supply the actual socket
peer or a separately validated trusted-proxy result, never a raw user-controlled
forwarded header. Each table is capped at 4,096 records by default (configurable
downward). Expired entries are cleaned opportunistically; active credentials are
not evicted merely to make room. Capacity exhaustion fails closed.

An optional audit callback receives fixed event names and, where known, the
principal, never passwords, hashes, tokens, headers or private backend errors.
Events cover account updates/disable, login success/denial/throttling, token issue/
revocation/denial and session revocation/denial. Routine successful credential
checks do not generate audit writes. Audit sink errors are logged generically and
do not alter authentication outcomes; a deployment requiring transactional audit
must provide a stronger integration rather than assuming this callback is durable.

### Store contract and deployment limits

The store supplies `transaction()` yielding an adapter with `get(table, key)`,
`put(table, key, value)`, `delete(table, key)` and `items(table)`. Values are detached
copies. Transactions serialize the whole block and roll back on exceptions;
`items` returns a stable snapshot, and deleting a missing key is harmless. The
namespaces are `accounts`, `sessions`, `tokens`, `attempts`. Records include account
revision, scopes and Unix expiry timestamps; use a trusted clock consistent across
workers. Sharing a store between service instances is an explicit choice and also
shares rate-limit counters. Durable adapters must preserve atomicity across
processes, protect stored password hashes and make account changes visible to all
workers. HTTPdis does not open or close a caller-owned store.

`MemoryAuthStore` is an explicitly chosen single-process adapter for development
and tests. Its data is lost on restart, including accounts, tokens and rate limits;
it provides **no restart durability or multi-process coordination**.

### Durable SQLite authentication

Install `httpdis[auth]` (Sonicprobe >= 0.3.55) to use the existing AnySQL SQLite
adapter with automatic reconnect disabled. The embedding daemon chooses the
filename, creates its private parent directory, and owns the store lifecycle:

```python
from httpdis.auth_sqlite import SQLiteAuthStore
from httpdis.auth_backend import LocalAuthService, Argon2Passwords

store = SQLiteAuthStore('/var/lib/my-daemon/auth/auth.db', timeout=5)
try:
    service = LocalAuthService(store, Argon2Passwords())
    # Supply service to your provider and trusted administration interface.
    # Stop request workers before closing the store.
finally:
    store.close()
```

There is no default filename and no automatic account creation. Existing Basic
and provider configurations are unaffected. The database must be a local regular
file, owned by the daemon user with no group/other permissions (created 0600).
The parent must be owned by that user and not writable by group/others; keep the
path and its ancestors under trusted administration. Symlinks, hard links and
replacement of an open store's file are rejected. Use a dedicated authentication
database, independent of job history. Network filesystems are not supported.

Each transaction opens its own AnySQL connection in the calling thread, takes
`BEGIN IMMEDIATE`, commits on success, and closes on every exit (rolling back
uncommitted work). `synchronous=FULL`, the DELETE journal and secure deletion are
selected explicitly. Lock waits are bounded by `timeout` (0 < seconds <= 30).
Multiple threads/processes can use the same database; create one store per process
after forking. Failures are surfaced without reconnect/replay or memory fallback.

Accounts, sessions, token revocations and rate-limit counters survive restart.
Passwords remain hashes; session/token/CSRF secrets are not stored in plaintext.
This is not encryption at rest: protect the database and backups as credentials.
Stop all writers before copying the database for backup. Only schema version 1
is accepted; incompatible databases are refused, never silently reset. JSON
records are bounded to 64 KiB and support the existing four namespaces. Redis
and automatic schema migrations are not supplied by this adapter.

### Browser session transport

`httpdis.auth_browser.BrowserAuthProvider(service, origin, cookie_prefix='httpdis')`
adds an opt-in cookie adapter over the same `LocalAuthService`. The daemon supplies
the service, backend, public origin and lifecycle; HTTPdis installs no routes.
`BearerAuthProvider` remains token-only and legacy Basic behavior is unchanged.

The provider's `login(AuthenticationRequest, principal, password)` returns the
existing redacted session grant. Send `provider.cookie(grant.secret, max_age)` as
`Set-Cookie`, and return only the CSRF value and identity to browser JavaScript.
Do not return the session secret in JSON or store it in browser JavaScript storage.
Use `provider.logout(request)` before sending `provider.expired_cookie()`.
Login rotates any previous cookie session, and logout requires the current CSRF.
The service already enforces password hashing, login limits, idle/absolute expiry,
account revision, disable and persistent revocation.

HTTPS cookies use `__Host-<prefix>-session`, `Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, a bounded `Max-Age`, and no Domain attribute. HTTP is accepted only for
literal `127.0.0.1` / `::1` development origins, with an unprefixed non-Secure cookie.
The configured origin must have no path; standard ports are canonicalized.
Use a dedicated origin: unrelated applications on the same origin share browser
security boundaries. Behind TLS termination, configure the external HTTPS origin,
preserve Host, and keep direct backend access private. Forwarded headers are never
trusted to choose the origin or weaken cookie policy.

Cookie reads require the configured Host and reject foreign Origin/fetch metadata.
Every cookie mutation requires exact Origin, JSON Content-Type and X-CSRF-Token.
Login requires the same Origin/JSON checks even before a session exists. Duplicate
security headers/cookies and mixed Bearer/session credentials are rejected. Explicit
Bearer clients without browser metadata continue to work without cookies or Origin.

Embedding requirements: serve only fixed public login/assets routes; protect all
business routes; bound login request bodies; prohibit CORS/preflight in browser
mode; apply no-store, CSP, frame denial and nosniff headers to errors as well as
successes; never log credentials, payloads or cookies. `require_browser` is exposed
for checking public routes before parsing their body. HTTPdis's historical generic
OPTIONS behavior is unchanged: override it in the embedding browser handler.
Application scopes, ownership and action confirmation remain application policy.
This adapter supplies no HTML UI, proxy configuration, TOTP or SSO.

