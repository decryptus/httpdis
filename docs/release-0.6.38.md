# HTTPdis 0.6.38

Access logs now omit the query string, fragment and authority of the request
target. For example, a request to `/probe/web?target=...` appears as
`GET /probe/web HTTP/1.1` with its response status and size. The handler
still receives the original query parameters.

Log parsers that extract query parameters from HTTPdis access logs need to
use application metrics or explicit, non-sensitive fields. URI validation
failures now return a generic HTTP 400 diagnostic. Review reverse proxy and
application log settings separately if they record the full incoming URL.

Install with `python -m pip install --upgrade httpdis==0.6.38`.
