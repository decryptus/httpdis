# Architecture review — 2026-09-27

Reviewed commit: `962cc6cc42cf55600e5bc4cf7d9fad8d5f29e422` on `master`.
Initial status: **review and engineering requirements only**. See the follow-up
implementation below for the addressed findings and compatibility scope.

Scope: separation of application logic, interfaces and adapters; callback and
initialization ownership; fixed validation contracts. Source files were fetched
at the pinned commit. This PR does not change runtime code or claim CI enforcement
of the new requirements. [Pinned source](https://github.com/decryptus/httpdis/tree/962cc6cc42cf55600e5bc4cf7d9fad8d5f29e422).

## Confirmed findings

### H1 — Medium: server state is owned by module globals

`httpdis/httpdis.py` stores routes in `_COMMANDS`, `_NCMD`, `_RCMD`, options in
`_OPTIONS`, authentication in `_AUTH`, and lifecycle in `_HTTP_SERVER`/`_KILLED`.
`init`, `register`, `run`, request handlers and `stop` share these values. A second
initialization changes the options/authentication seen by the same module's
handlers; routes are not scoped to a server instance. This is an embedding and
composition limitation, not evidence that the API launches a CLI.

A reusable runtime/router object should own that state, with an explicit lifecycle
adapter. Acceptance: two servers with different routes/options/authentication
operate independently, including start/stop and rejected requests. Keep existing
transport contract tests and decide compatibility for global entry points.

### H2 — Low: the default-options schema is duplicated

`httpdis/config.py:DEFAULT_OPTIONS` and `httpdis/httpdis.py:DEFAULT_OPTIONS` define
the same keys separately. Centralize the schema and keep compatibility exports
where current consumers require them. Verify both access paths give independent
mutable option dictionaries without diverging defaults.

## Positive evidence and limits

HTTPdis is itself an HTTP transport; request classes, headers, status codes and
route matching are legitimate here. No CLI, argparse or curses import was found
in the five package Python files. Its handlers call registered functions directly.
Authentication credentials use `threading.local()` and are cleared for each
validation; the older shared-user race is not asserted against this reviewed
commit. Thread-local credentials do not isolate two separately configured servers.
This review traced source behavior; it does not claim new socket/concurrency tests
or a complete security audit. Business services supplied by consumers require
separate callback-level review.


## Follow-up implementation

H1: `HttpServerContext` owns route maps, options, authentication and lifecycle.
Handlers resolve the bound context, and context startup derives a handler subclass
without mutating the shared handler class. The default context explicitly adapts
the historical module globals and function signatures. Global entry points are
still shared; only explicitly separate contexts provide server isolation.

H2: `httpdis.py` obtains its compatibility defaults from `config.get_default_options()`;
the duplicate schema is removed and both import paths remain independent copies.

Tests run two real servers concurrently with separate named/regex routes, users,
realms, body limits and server headers. They verify rejection paths, concurrent
authentication, changes to legacy globals, stopping one server without affecting
the other, global startup/shutdown, startup failure cleanup and opt-in context
signal handlers. Import-blocked tests reject application/CLI dependencies.
The CI also installs the candidate package and runs pinned DWho, Auton, Covenant
and Monit Docker suites outside the HTTPdis checkout, in addition to legacy and
modern Python matrices and distribution checks.

Remaining scope: callback-owned application state is not isolated by HTTPdis;
routes/configuration are prepared before serving, and existing worker shutdown
semantics do not cancel application code already executing.
