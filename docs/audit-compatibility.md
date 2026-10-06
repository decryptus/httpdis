# Audit correction compatibility

Ambiguous or malformed request lengths now produce HTTP 400 before authentication
or handler execution. Identical repeated Content-Length values remain accepted.
Transfer-Encoding with Content-Length is rejected; unsupported transfer codings
produce HTTP 400, preserving the strict framing contract used by consumers. These checks also apply to GET, HEAD and OPTIONS.

HEAD responses carry the corresponding GET representation length without a body.
Responses with status 204 and 304 omit Content-Length; status 205 uses zero.
Bodyless responses do not transmit a payload.

A handler registered for several HTTP methods now runs its lifecycle callbacks
once per registration. Distinct registrations sharing a callback still each run.
Server creation/startup failures clean up entered lifecycle phases and preserve
the original exception even if cleanup also fails.

Content-Disposition no longer requires the legacy RFC6266 parser/Werkzeug chain.
The focused transport helper supports quoted filenames and UTF-8 extended
filenames and rejects control characters in header input/output.

Modern package builds require setuptools 83 or newer on Python 3.10+.
Legacy interpreter constraints remain and are not covered by modern dependency
security validation. Use the coordinated Sonicprobe correction as well.
