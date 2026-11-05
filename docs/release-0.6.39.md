# HTTPdis 0.6.39

When a handler raises `HttpReqError` with exception information, or calls
`send_exception` directly, HTTPdis returns the standard reason for the
selected status. For example, a 503 response keeps its `Retry-After` header
and the JSON handler reports `Service Unavailable`. The client receives no
Python traceback or exception text. The log entry for this path records the
status code.

Upgrade with `python -m pip install --upgrade httpdis==0.6.39`.
