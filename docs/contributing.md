# Contributor documentation

This guide is for people changing or maintaining httpdis. For installation, configuration and everyday use, start with the [user documentation](https://github.com/decryptus/httpdis/blob/master/README.md).

## Development and publication

```sh
python -m pip install -e . mock
python -m unittest discover -s tests -v
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
```

Update `VERSION`, `RELEASE` and `setup.yml` together. After tests and distribution
validation succeed, the master publication workflow creates `vX.Y.Z` and uploads
via Trusted Publishing (`decryptus/httpdis`, `pypi.yml`, environment `pypi`).
Already-tagged versions are not replaced by ordinary master commits.

License: GPL-3.0-or-later. Original authors and Wazo/Proformatique copyrights are
preserved in the source files.

See the [September 2026 code and architecture review](https://github.com/decryptus/httpdis/blob/master/docs/REVIEW.md) (French).

## Documentation rules

Keep user instructions and contributor material separate. The repository [engineering requirements](https://github.com/decryptus/httpdis/blob/master/AGENTS.md) define the review and validation rules. Preserve user-facing compatibility, security and recovery guidance when moving internal explanations.
