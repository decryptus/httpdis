"""HTTPDIS EXT JSON"""

__version__ = "$Revision$ $Date$"
__license__ = """
    Copyright (C) 2018 doowan

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import json
import logging

from httpdis import httpdis
from httpdis.httpdis import (init,
                             HttpReqError,
                             HttpReqErrJson,
                             HttpResponse,
                             HttpResponseJson,
                             get_default_options,
                             register,
                             sigterm_handler,
                             stop)


LOG             = logging.getLogger('httpdis.ext.json') # pylint: disable-msg=C0103
CONTENT_TYPE    = 'application/json'
DEFAULT_CHARSET = 'utf-8'


def _encode_if(value, encoding=DEFAULT_CHARSET):
    # transform value returned by json.loads to something similar to what
    # cjson.decode would have returned
    if isinstance(value, unicode):
        return value.encode(encoding)
    elif isinstance(value, list):
        return [_encode_if(v, encoding) for v in value]
    elif isinstance(value, dict):
        return dict((_encode_if(k, encoding), _encode_if(v, encoding)) for
                    (k, v) in value.iteritems())
    else:
        return value


class HttpReqHandler(httpdis.HttpReqHandler):
    _DEFAULT_CONTENT_TYPE   = CONTENT_TYPE
    _EXCEPTED_CONTENT_TYPES = (CONTENT_TYPE,)

    def parse_payload(self, data, charset):
        return _encode_if(json.loads(data), charset)

    def response_dumps(self, data):
        return json.dumps(data)


def run(options, http_req_handler = HttpReqHandler):
    return httpdis.run(options, http_req_handler)
