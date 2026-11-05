# HTTPdis 0.6.37

Upgrade with `python -m pip install --upgrade httpdis==0.6.37`.

Handlers using Basic authentication receive the authorized username in
`HTTP_AUTH_USER`. Replace any use of `HTTP_AUTH_PASSWD` or
`HttpAuthentication.passwd` before upgrading. Use an application credential
for outbound services that require their own authentication.

Older htpasswd files continue to work. A startup warning identifies SHA-1 or
traditional DES formats so operators can migrate the affected entries.
See the [Basic authentication guide](../README.md#authentication-and-deployment).
