# -*- coding: utf-8 -*-
# Copyright 2018-2019 Adrien Delle Cave
# SPDX-License-Identifier: GPL-3.0-or-later
"""httpdis.ext.json"""

import json
import logging

from six import binary_type, ensure_str, iteritems, text_type

from httpdis import httpdis
# pylint: disable=unused-import
from httpdis.httpdis import (init,
                             HttpReqError,
                             HttpReqErrJson,
                             HttpResponse,
                             HttpResponseJson,
                             get_default_options,
                             register,
                             sigterm_handler,
                             stop)


LOG                 = logging.getLogger('httpdis.ext.json') # pylint: disable-msg=C0103
CONTENT_TYPE        = 'application/json'
DEFAULT_CHARSET     = 'utf-8'

HTTP_RESPONSE_CLASS = HttpResponseJson
HTTP_REQERROR_CLASS = HttpReqErrJson


def _encode_if(value, encoding=DEFAULT_CHARSET):
    # transform value returned by json.loads to something similar to what
    # cjson.decode would have returned
    if isinstance(value, (text_type, binary_type)):
        return ensure_str(value, encoding)
    if isinstance(value, list):
        return [_encode_if(v, encoding) for v in value]
    if isinstance(value, dict):
        return dict((_encode_if(k, encoding), _encode_if(v, encoding)) for
                    (k, v) in iteritems(value))
    return value


class HttpReqHandler(httpdis.HttpReqHandler):
    _DEFAULT_CONTENT_TYPE  = CONTENT_TYPE
    _ALLOWED_CONTENT_TYPES = [CONTENT_TYPE,
                              'application/x-www-form-urlencoded']
    _FUNC_SEND_ERROR       = 'send_error_json'

    @staticmethod
    def parse_payload(data, charset):
        return _encode_if(json.loads(data), charset)

    @staticmethod
    def response_dumps(data, charset):
        return json.dumps(_encode_if(data, charset))

    def _mk_error_explain_data(self, code, message, explain, charset):
        return self.response_dumps({'code':    code,
                                    'message': message,
                                    'explain': explain},
                                   charset)


def run(options, http_req_handler = HttpReqHandler):
    return httpdis.run(options, http_req_handler)
