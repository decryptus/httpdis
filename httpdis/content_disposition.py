# -*- coding: utf-8 -*-
"""Content-Disposition helpers used by static responses, without a web framework."""
from collections import namedtuple
from email.message import Message
from email.utils import collapse_rfc2231_value
import re
from six import ensure_text, ensure_binary
from six.moves.urllib.parse import quote

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9a-zA-Z-]+\Z")
_Disposition = namedtuple('ContentDisposition', 'disposition filename_unsafe')


def _text(value):
    value = ensure_text(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('Control character in Content-Disposition')
    return value


def parse_headers(value):
    value = _text(value)
    disposition = value.split(';', 1)[0].strip().lower()
    if not _TOKEN.match(disposition):
        raise ValueError('Invalid Content-Disposition type')
    message = Message()
    message['Content-Disposition'] = value
    filename = message.get_filename()
    for name, parameter in message.get_params(header='content-disposition', unquote=True)[1:]:
        if name.lower() == 'filename' and isinstance(parameter, tuple):
            filename = collapse_rfc2231_value(parameter)
            break
    return _Disposition(disposition, filename)


def build_header(filename, disposition='attachment'):
    filename, disposition = _text(filename), _text(disposition)
    if not _TOKEN.match(disposition):
        raise ValueError('Invalid Content-Disposition type')
    fallback = ''.join(char if ord(char) < 128 else '_' for char in filename)
    quoted = fallback.replace('\\', '\\\\').replace('"', '\\"')
    result = '%s; filename="%s"' % (disposition, quoted)
    if fallback != filename:
        result += "; filename*=UTF-8''" + quote(ensure_binary(filename), safe='')
    return result
