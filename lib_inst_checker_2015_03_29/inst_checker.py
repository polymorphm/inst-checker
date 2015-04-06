# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

from urllib import parse as url_parse
from urllib import request as url_request
from http import cookiejar
import json
import time

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
    email_iter = inst_checker_ctx.email_iter
    
    login_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/login/')
    edit_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/edit/')
    password_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/password/change/')
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
    
    print('***', 'fetch login_url OK', '***')
    
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
        raise InstCheckerError('post login_ajax_url error')
    
    data = json.loads(resp.read(REQUEST_READ_LIMIT).decode())
    
    if not isinstance(data, dict):
        raise InstCheckerError('invalid answer format (#1)')
    
    is_auth = data.get('authenticated')
    
    if not isinstance(is_auth, bool):
        raise InstCheckerError('invalid answer format (#2)')
    
    inst_checker_ctx.is_auth = is_auth
    
    if email_iter is None or \
            not inst_checker_ctx.is_auth:
        return
    
    csrftoken = cookies._cookies[INSTAGRAM_DOMAIN]['/']['csrftoken'].value
    new_email = next(email_iter)
    new_username = '{}_1'.format(username)
    new_password = '{}_1'.format(password)
    
    print('***', new_email, new_username, new_password, '***')
    
    resp = open_func(
        opener,
        url_request.Request(
            edit_url,
            headers={
                'User-Agent': ua_name,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != edit_url:
        raise InstCheckerError('fetch edit_url error')
    
    print('***', 'fetch edit_url OK', '***')
    
    csrftoken = cookies._cookies[INSTAGRAM_DOMAIN]['/']['csrftoken'].value
    
    resp = open_func(
        opener,
        url_request.Request(
            edit_url,
            data=url_parse.urlencode({
                'csrfmiddlewaretoken': csrftoken,
                'email': new_email,
                'username': new_username,
                'first_name': '',
                'phone_number': '',
                'gender': '3',
                'biography': '',
                'external_url': '',
                'chaining_enabled': 'on',
            }).encode(),
            headers={
                'User-Agent': ua_name,
                'Referer': edit_url,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != edit_url:
        raise InstCheckerError('post edit_url error')
    
    print('***', 'post edit_url OK' ,'***')
    
    inst_checker_ctx.new_username = new_username
    inst_checker_ctx.new_email = new_email
    
    return
    
    ##########################
    ##########
    
    csrftoken = cookies._cookies[INSTAGRAM_DOMAIN]['/']['csrftoken'].value
    
    resp = open_func(
        opener,
        url_request.Request(
            password_url,
            headers={
                'User-Agent': ua_name,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != password_url:
        raise InstCheckerError('fetch password_url error')
    
    print('***', 'fetch password_url OK', '***')
    
    csrftoken = cookies._cookies[INSTAGRAM_DOMAIN]['/']['csrftoken'].value
    
    resp = open_func(
        opener,
        url_request.Request(
            password_url,
            data=url_parse.urlencode({
                'csrfmiddlewaretoken': csrftoken,
                'old_password': password,
                'new_password1': new_password,
                'new_password2': new_password,
            }).encode(),
            headers={
                'User-Agent': ua_name,
                'Referer': password_url,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    print('*****', resp.geturl(), '*****')
    
    if resp.getcode() != 200 or resp.geturl() != password_url:
        raise InstCheckerError('post password_url error')
    
    #inst_checker_ctx.new_password = new_password
    

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
    inst_checker_ctx.email_iter = None
