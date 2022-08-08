# -*- coding: utf-8 -*-
# Copyright 2008-2019 The Wazo Authors
# SPDX-License-Identifier: GPL-3.0-or-later
"""httpsdis.config"""


BUFFER_SIZE      = 65536
DEFAULT_CHARSET  = 'utf-8'

DEFAULT_OPTIONS  = {'auth_basic':      None,
                    'auth_basic_file': None,
                    'testmethods':     False,
                    'max_body_size':   1 * 1024 * 1024,
                    'max_workers':     1,
                    'max_requests':    0,
                    'max_life_time':   0,
                    'listen_addr':     None,
                    'listen_port':     None,
                    'server_version':  None,
                    'sys_version':     None}


def get_default_options():
    return DEFAULT_OPTIONS.copy()
