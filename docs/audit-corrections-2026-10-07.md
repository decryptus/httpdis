# Audit corrections — 2026-10-07

Candidate corrections across DWho, HTTPdis and Sonicprobe. These branches are
prepared for review; no release/version reconciliation or Textual merge is
included in this correction set.

| Finding | Before | After | Regression coverage |
| --- | --- | --- | --- |
| Disabled inotify plugin | A nonempty disabled mapping could select/execute a plugin | Explicit global enablement, path restriction, worker recheck and disabled lifecycle suppression | DWho InotifyAuditTests |
| Ambiguous HTTP framing | Contradictory lengths could reach authentication/dispatch | Reject before authentication for request methods, keep identical repeated lengths | HTTPdis FramingAuditTests |
| Vulnerable dependency chain | Legacy RFC6266/Werkzeug chain and old crypto pins | Focused header helper; modern CSR API; pyOpenSSL 26.4, cryptography 50.x, modern setuptools | DispositionAuditTests, GenCert tests, runtime dependency audit |
| Notification filters | Invalid explicit tags could normalize to broad selection | Strict explicit invalid/empty tags raise before delivery | DWho NotificationAuditTests |
| Duplicate lifecycle callbacks | One registration for several methods could initialize repeatedly | Deduplicate registration objects, preserve distinct registrations | HTTPdis LifecycleAuditTests |
| Failed startup cleanup | Bind/start errors could bypass resource cleanup | Clean entered phases and retain the original failure | HTTPdis LifecycleAuditTests |
| SQL LIKE literals | Percent/underscore escaping lacked an explicit SQL escape | Parameterized LIKE with ESCAPE '!' and literal metacharacters | DWho SQLAuditTests (SQLite) |
| HEAD/bodyless length | HEAD length could differ from GET | GET-equivalent byte length for HEAD; compliant bodyless responses | HTTPdis FramingAuditTests |

## Validation

Python 3.12; candidate packages built and installed outside source checkouts.
Changed installed Python modules were compared byte-for-byte with candidates.
Collection guards passed before each suite.

| Suite | Cases | Passed | Skipped |
| --- | ---: | ---: | ---: |
| Sonicprobe unit tests | 204 | 203 | 1 |
| Sonicprobe integration | 4 | 4 | 0 |
| DWho unit/integration declarations | 96 | 93 | 3 |
| HTTPdis tests | 69 | 68 | 1 |
| CI collection helper tests (18 per repository) | 54 | 51 | 3 |
| Total | 427 | 419 | 8 |

Skips: one process namespace-dependent Sonicprobe test, three disposable-Redis
DWho tests, one optional Argon2 HTTPdis test, and one pytest-specific helper case
per repository under the unittest runner. Other Python versions were not executed
locally; the retained CI interpreter matrix remains a release gate.

The Sonicprobe integration suite initially lacked Auton/Covenant. After installing
those consumers for the exercised lock contracts, all four cases passed. This is
not a claim that their entire application suites were run. GenCert has eight
passing cases including modern CSR return/export, extensions and invalid signature
rejection. Legacy dependency paths were preserved but not security-cleared.

`pip check` passed for the three candidate libraries. All three Sphinx documentation
builds passed with warnings treated as errors.

The resolved runtime closure contains 29 packages. pip-audit reported **no known
vulnerabilities** for that exact closure on 2026-10-07. This is not a guarantee
against unknown vulnerabilities, and does not cover old-Python dependency paths
or the separate documentation/test environment. The initial report's eight
advisory entries included duplicates; the final scan is empty.

Tested crypto/build versions: pyOpenSSL 26.4.0, cryptography 50.0.2 and setuptools
84.0.0. The obsolete CSR API removal is documented in the
[upstream changelog](https://www.pyopenssl.org/en/latest/changelog.html).
See Sonicprobe's user-facing GenCert migration guide before updating callers.

## Delivery boundary

The ninth audit item (published distributions differing from source) remains for
coordinated versioning, CI and release publication. Existing branches are the
reviewable delivery for these eight corrections. No package publication is claimed.
