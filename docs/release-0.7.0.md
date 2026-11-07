# HTTPdis 0.7.0

Disable SHA-1 and traditional DES Basic password hashes by default.

Review existing htpasswd entries before upgrading. Replace SHA-1 and traditional
DES entries with bcrypt on a system that supports it (for example, run
`htpasswd -B /path/to/htpasswd alice`). Modern entries in a mixed file remain
usable. For a temporary migration window set the boolean
`auth_basic_allow_legacy_hashes: true`. Remove the option after replacing the
old hashes. The startup warning identifies affected formats without account names.
