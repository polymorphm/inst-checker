# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

from urllib import parse as url_parse
from urllib import request as url_request
import json
import random

USERAGENT_LIST_URL = 'https://getuseragent.blogspot.com/2014/03/getuseragent.html'
REQUEST_TIMEOUT = 60.0
REQUEST_READ_LIMIT = 10000000

def get_useragent_list():
    marker_prefix = 'USERAGENT_DATA'
    start_marker = '\x3c!--{}_START'.format(marker_prefix)
    stop_marker = '{}_STOP--\x3e'.format(marker_prefix)
    
    opener = url_request.build_opener()
    opener_res = opener.open(
        url_request.Request(USERAGENT_LIST_URL),
        timeout=REQUEST_TIMEOUT,
    )
    raw_data = opener_res.read(REQUEST_READ_LIMIT).decode(errors='replace')
    start_pos = raw_data.find(start_marker)
    stop_pos = raw_data.find(stop_marker)
    
    if start_pos == -1 or stop_pos == -1:
        raise ValueError(
            'not found: start_marker or stop_marker',
        )
    
    useragent_raw_data = raw_data[start_pos+len(start_marker):stop_pos]
    useragent_data = json.loads(useragent_raw_data)
    
    if not isinstance(useragent_data, (tuple, list)):
        raise ValueError(
            'useragent_data is not isinstance of tuple-or-list',
        )
    
    for useragent_item in useragent_data:
        if not isinstance(useragent_item, str) or \
                '\n' in useragent_item or '\r' in useragent_item:
            continue
        
        yield useragent_item

class GetUseragentFunc:
    def __init__(self):
        self.useragent_list = tuple(get_useragent_list())
    def __call__(self):
        return random.choice(self.useragent_list)
