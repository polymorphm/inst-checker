# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

from urllib import parse as url_parse
from urllib import request as url_request
from http import cookiejar
import json
import time
import socket
import imaplib
from email import parser as email_parser
import re

INSTAGRAM_DOMAIN = 'instagram.com'
INSTAGRAM_URL = 'https://{}/'.format(INSTAGRAM_DOMAIN)

REQUEST_TIMEOUT = 60.0
REQUEST_READ_LIMIT = 10000000

class InstCheckerError(Exception):
    pass

class InstCheckerCtx:
    pass

class SafeIMAP4(imaplib.IMAP4):
    def _create_socket(self):
        sock = socket.create_connection(
                (self.host, self.port),
                timeout=15.0,
                )
        
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        return sock

def mail_fetch(email, imap_host, email_login, email_pass):
    try:
        imap = SafeIMAP4(host=imap_host)
        imap.starttls()
        imap.login(email_login, email_pass)
        try:
            imap.select()
            typ, search_data = imap.search(None, 'UNSEEN')
            
            for num in reversed(search_data[0].split()):
                typ, fetch_data = imap.fetch(num, '(RFC822)')
                
                msg_parser = email_parser.BytesFeedParser()
                msg_parser.feed(fetch_data[0][1])
                msg = msg_parser.close()
                
                msg_from = msg.get_all('from')
                msg_to = msg.get_all('to')
                msg_subject = msg.get_all('subject')
                
                print('######', 'msg_from: ', msg_from)
                print('######', 'msg_to: ', msg_to)
                print('######', 'msg_subject: ', msg_subject)
                
                if not msg_from or tuple(msg_from) != ('"Instagram" <no-reply@mail.instagram.com>',) or \
                        not msg_to or tuple(msg_to) != (email,) or \
                        not msg_subject or tuple(msg_subject) != ('Confirm your email address for Instagram',):
                    continue
                
                print('######', 'YESSS!!')
                
                for msg_part in msg.walk():
                    if msg_part.get_content_type() == 'text/plain':
                        payload = msg_part.get_payload(decode=True)
                        
                        assert isinstance(payload, bytes)
                        
                        msg_text = payload.decode(errors='replace')
                        
                        return msg_text
        finally:
            imap.close()
            imap.logout()
    except imaplib.IMAP4.error as imap_error:
        error_str = 'email is {!r}, error is {!r}'.format(
                email,
                imap_error,
                )
        raise imaplib.IMAP4.error(error_str)

def unsafe_check(inst_checker_ctx):
    ua_name = inst_checker_ctx.ua_name
    cookies = inst_checker_ctx.cookies
    opener = inst_checker_ctx.opener
    open_func = inst_checker_ctx.open_func
    username = inst_checker_ctx.username
    password = inst_checker_ctx.password
    
    login_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/login/')
    login_ajax_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/login/ajax/')
    
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

def unsafe_edit(inst_checker_ctx):
    ua_name = inst_checker_ctx.ua_name
    cookies = inst_checker_ctx.cookies
    opener = inst_checker_ctx.opener
    open_func = inst_checker_ctx.open_func
    username = inst_checker_ctx.username
    password = inst_checker_ctx.password
    email_iter = inst_checker_ctx.email_iter
    
    edit_url = url_parse.urljoin(INSTAGRAM_URL, 'accounts/edit/')
    
    if email_iter is None or \
            not inst_checker_ctx.is_auth:
        return
    
    new_username = '{}_1'.format(username)
    new_email_line = next(email_iter)
    new_email_line_split = new_email_line.split(sep=':')
    
    if len(new_email_line_split) < 2:
        raise InstCheckerError('invalid new_email_line')
    
    new_email = new_email_line_split[0]
    new_email_password = new_email_line_split[1]
    
    print('***', new_username, new_email, '***')
    
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
    inst_checker_ctx.is_edit_begin = True
    
    mail_ru_imap_host = 'imap.mail.ru'
    yandex_ru_imap_host = 'imap.yandex.ru'
    
    if new_email.endswith('@mail.ru') or \
            new_email.endswith('@inbox.ru') or \
            new_email.endswith('@list.ru') or \
            new_email.endswith('@bk.ru'):
        email_login = new_email
        imap_host = mail_ru_imap_host
    elif new_email.endswith('@yandex.ru'):
        email_login = new_email
        imap_host = yandex_ru_imap_host
    else:
        raise InstCheckerError('unknown email service')
    
    if '+' in email_login and '@' in email_login:
        fixed_email_login = '{}{}'.format(
            email_login[:email_login.find('+')],
            email_login[email_login.rfind('@'):]
        )
        
        if len(fixed_email_login) <= len(email_login):
            email_login = fixed_email_login
    
    for att_i in range(10):
        time.sleep(10)
        
        try:
            mail_text = mail_fetch(new_email, imap_host, email_login, new_email_password)
        except socket.timeout:
            continue
        
        if mail_text is None:
            continue
        
        assert isinstance(mail_text, str)
        
        confirm_url_prefix = 'https://instagram.com/accounts/confirm_email/'
        confirm_url_match = re.search(
                r'\[(?P<confirm_url>' + re.escape(confirm_url_prefix) + r'\S+)\]',
                mail_text,
                flags=re.S,
                )
        
        if confirm_url_match is None:
            continue
        
        confirm_url = confirm_url_match.group('confirm_url')
        
        break
    else:
        raise InstCheckerError(
                'confirm_url not received',
                )
    
    print('#####', 'confirm_url: ', confirm_url)
    
    resp = open_func(
        opener,
        url_request.Request(
            confirm_url,
            headers={
                'User-Agent': ua_name,
            },
        ),
        timeout=REQUEST_TIMEOUT,
    )
    
    if resp.getcode() != 200 or resp.geturl() != confirm_url:
        raise InstCheckerError('fetch confirm_url error')
    
    print('***', 'fetch confirm_url OK', '***')
    
    inst_checker_ctx.is_edit = True

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
    inst_checker_ctx.is_auth = None
    inst_checker_ctx.email_iter = None
    inst_checker_ctx.is_edit_begin = False
    inst_checker_ctx.is_edit = False
