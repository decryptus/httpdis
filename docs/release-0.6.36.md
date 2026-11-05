# HTTPdis 0.6.36

Upgrade with `python -m pip install --upgrade httpdis==0.6.36`.

Browser frontends on a separate origin now need explicit permission for
preflighted requests. Register the frontend origin on each route and method
it uses, for example `cors_origins=['https://console.example.org']`.
The actual request still goes through the route's authentication checks.
Same-origin frontends and server-to-server API clients require no CORS setup.

Keep CSRF checks on state-changing routes. Browsers can send simple requests
without preflight and may reuse a preflight grant cached before the upgrade.
See the [CORS configuration guide](../README.md#browser-access-from-a-separate-origin-cors)
for the allowed headers, origin format and a complete registration example.
