# HTTPdis 0.6.35

Upgrade with `python -m pip install --upgrade httpdis==0.6.35`.

The default HTTP and JSON handlers now allow 10 seconds for the request line
and headers together. The body gets a separate budget of 10 seconds plus
one second per 32 KiB, up to 120 seconds. A client that exceeds the header
deadline loses the connection. A body read timeout returns HTTP 408.

Queries accept up to 1,024 ampersand-separated fields and 32 bracket levels
per name. Requests over either limit receive HTTP 414. Repeated array fields
within those limits retain their indices and take linear time to parse.

For large uploads or high-latency clients, see the handler settings in the
[request read deadlines guide](../README.md#request-read-deadlines-and-query-limits).
