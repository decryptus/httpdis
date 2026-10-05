# Engineering requirements

These are maintainer requirements. Existing violations are debt, not examples.
See [the architecture review](docs/architecture-review-2026-09-27.md).

- Business/application behavior must be callable independently of CLI, ncurses,
  web presentation and HTTP request objects. Interfaces translate input, call
  shared services and present results; they are not application engines.
- Never implement an API operation by importing/calling a CLI entry point,
  constructing artificial command arguments or delegating to UI-owned callbacks.
- Put HTTP decoding, headers, status mapping and serialization in transport
  adapters; terminal interaction and exit codes belong to command interfaces.
  Pass explicit data and caller identity to services, with domain results/errors.
- Keep authorization and operation validation server-side. Interface filtering
  and disabled controls do not grant permission or replace service validation.
- Use explicit adapters/composition for storage, execution, clocks and lifecycle.
  Avoid new process-global mutable application state and hidden import side effects.
- Declare fixed routes, field sets, schemas, registries, limits and regex patterns
  as named uppercase module constants. Dynamic per-request objects remain local.
- Centralize identifier validation and use full matching. Preserve this project's
  naming and selector contracts; do not copy Galliflow's grammar here.
- Bound externally supplied regex work where supported, preserve matching semantics,
  and reject invalid selectors explicitly without broadening their selection.
- Reuse DWho, HTTPdis and Sonicprobe according to their roles. A transport library
  may expose HTTP objects; neutral services must not require those objects.
- Inspect lazy imports, callbacks and initialization paths during reviews. For a
  refactor, add behavioral tests with interface imports blocked and fake adapters;
  green functional tests alone do not demonstrate architectural separation.
- Avoid unnecessary production log/disk writes, retaining promised durability.
  Do not claim documentation alone is an automated architecture gate.

## HTTPdis boundaries

- HTTPdis is an HTTP transport library. Routing, request/response types, auth
  decoding and wire errors belong here; application business policy does not.
- Handler callbacks delegate to services with explicit values and caller identity.
  No API-to-CLI dependency or terminal formatting inside handlers/services.
- Keep server routes, authentication, options and shutdown state instance-owned
  when introducing reusable server contexts. Do not assert multi-server isolation
  while the legacy global API is in use.
- Preserve request-local authentication and existing HTTP behavior. Thread-local
  credentials do not provide isolation between independently configured servers.
- Centralize the duplicated default-options schema; retain compatibility exports
  if required by current consumers rather than silently changing imports.

## Test discovery and execution

- Verify the actual runner and every discovery root before adding or changing
  tests. A green command does not prove that all test declarations were loaded.
  Do not put standalone pytest functions into a suite run only by unittest.
- Run `.github/scripts/check-test-collection.py` with Python, the same
  interpreter/environment as the tests, and the declared runner. Pass separately
  discovered directories together when they are nested. The guard compares
  declarations in `test*.py` files with actual collection; it does not run tests.
- Reject empty suites, import/collection errors, duplicate definitions and
  declarations omitted by the runner. Keep test helpers out of the `test*`
  namespace. Explain intentional skips and separate integration prerequisites;
  never hide failures with `continue-on-error` or `|| true`.
- Run the normal test command after the guard. Report collected/executed/skipped
  counts and investigate unexpected changes; collection alone is not a passing
  test run. Parameterization may produce several cases per declaration.
- Check test paths, naming patterns, selection filters and CI commands together.
  A new test directory or non-Python test harness needs an explicit CI entry;
  this guard only covers the directories and Python naming pattern passed to it.
- Verify installed-package tests outside the source checkout where applicable.
  Architecture scans must resolve the package under test and reject empty scans.
- Preserve supported interpreter matrices. Changing runners requires an explicit
  decision and collection parity; this Python 3.8+ CI helper does not replace
  legacy-interpreter execution or integration/system acceptance tests.

Current project runner: `unittest` for `tests`. CI helper tests use
`unittest` in `.github/tests`.

## Separate user and contributor documentation

- Maintain two distinct entry points and tables of contents: user documentation
  for installation, configuration, operation, public APIs and troubleshooting;
  contributor documentation for architecture, internals, tests, benchmarks,
  release engineering and development plans.
- Keep README and package descriptions focused on users. Link to the contributor
  guide instead of embedding maintainer procedures. Library API examples belong
  in the user guide when they are needed to integrate the library.
- Keep registry publishing, CI setup, repository secrets and maintainer account
  configuration out of user guides, website manuals and package descriptions.
  Never include credential values or private infrastructure evidence in either guide.
- Put implementation reviews and acceptance records under the contributor
  navigation. Preserve user-facing compatibility limits, migration instructions,
  security requirements and failure semantics in the user documentation.
- Apply this separation to generated documentation and FR/EN website content.
  Update source content and generators together; do not patch only generated HTML.
- Before delivery, inspect both entry points, check links and build documentation
  with warnings treated as errors where supported. Review README/package text and
  the deployed manual for accidental maintainer content. Preserve private-project
  visibility and existing review/publication approval requirements.
