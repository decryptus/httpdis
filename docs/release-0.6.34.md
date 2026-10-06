# httpdis 0.6.34

- Reject conflicting Content-Length headers before authentication.
- Preserve distinct lifecycle callbacks and clean up failed startup.
- Return correct HEAD Content-Length without writing a response body.
- Remove obsolete RFC6266 dependencies and cover audit regressions.

See [audit validation and remaining limits](audit-corrections-2026-10-07.md).

Install with `python -m pip install httpdis==0.6.34`.
