# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

from urllib import parse as url_parse
from urllib import request as url_request
from http import cookiejar
import json

INSTAGRAM_DOMAIN = 'instagram.com'
INSTAGRAM_URL = 'https://{}/'.format(INSTAGRAM_DOMAIN)

REQUEST_TIMEOUT = 60.0
REQUEST_READ_LIMIT = 10000000

class InstCheckerError(Exception):
    pass

class InstCheckerCtx:
    pass

def unsafe_check(inst_checker_ctx):
    ua_name = inst_checker_ctx.ua_name
    cookies = inst_checker_ctx.cookies
    opener = inst_checker_ctx.opener
    open_func = inst_checker_ctx.open_func
    username = inst_checker_ctx.username
    password = inst_checker_ctx.password
    
    login_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/login/')
    login_ajax_url = login_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/login/ajax/')
    
    resp = open_func(
        opener,
        url_request.Request(
            login_url,
            headers={
                'User-Agent': ua_name,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != login_url:
        raise InstCheckerError('fetch login_url error')
    
    csrftoken = cookies._cookies[INSTAGRAM_DOMAIN]['/']['csrftoken'].value
    
    resp = open_func(
        opener,
        url_request.Request(
            login_ajax_url,
            data=url_parse.urlencode({
                'username': username,
                'password': password,
            }).encode(),
            headers={
                'User-Agent': ua_name,
                'Referer': login_url,
                'X-CSRFToken': csrftoken,
                'X-Requested-With': 'XMLHttpRequest',
                'X-Instagram-AJAX': '1',
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != login_ajax_url:
        raise InstCheckerError('fetch login_ajax_url error')
    
    data = json.loads(resp.read(REQUEST_READ_LIMIT).decode())
    
    if not isinstance(data, dict):
        raise InstCheckerError('invalid answer format (#1)')
    
    is_auth = data.get('authenticated')
    
    if not isinstance(is_auth, bool):
        raise InstCheckerError('invalid answer format (#2)')
    
    inst_checker_ctx.is_auth = is_auth

def init_inst_checker_ctx(inst_checker_ctx, ua_name, username, password):
    cookies = cookiejar.CookieJar()
    opener = url_request.build_opener(
        url_request.HTTPCookieProcessor(cookiejar=cookies),
    )
    
    def open_func(opener, *args, **kwargs):
        return opener.open(*args, **kwargs)
    
    inst_checker_ctx.ua_name = ua_name
    inst_checker_ctx.cookies = cookies
    inst_checker_ctx.opener = opener
    inst_checker_ctx.open_func = open_func
    inst_checker_ctx.username = username
    inst_checker_ctx.password = password
