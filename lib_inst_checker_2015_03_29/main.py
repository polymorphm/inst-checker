# -*- mode: python; coding: utf-8 -*-

assert str is not bytes

import os, os.path
import threading
from . import inst_checker
from . import get_useragent_func

def try_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except (ValueError, OSError):
        pass

def safe_check(inst_checker_ctx):
    def thread_func():
        try:
            inst_checker.unsafe_check(inst_checker_ctx)
        except Exception as e:
            error_type = type(e)
            error_str = str(e)
            
            inst_checker_ctx.error_type = error_type
            inst_checker_ctx.error_str = error_str
        else:
            inst_checker_ctx.error_type = None
            inst_checker_ctx.error_str = None
    
    thr = threading.Thread(target=thread_func)
    thr.start()
    thr.join()
    
    return inst_checker

def main():
    in_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'in.txt')
    out_good_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'out_good.txt')
    out_bad_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'out_bad.txt')
    
    get_useragent = get_useragent_func.GetUseragentFunc()
    
    in_fd = open(in_path, mode='r', encoding='utf-8', errors='replace')
    out_good_fd = open(out_good_path, mode='w', encoding='utf-8', newline='\n')
    out_bad_fd = open(out_bad_path, mode='w', encoding='utf-8', newline='\n')
    
    for in_line in in_fd:
        line = in_line.strip()
        in_line_split = line.split(sep=':')
        
        if len(in_line_split) != 2:
            continue
        
        ua_name = get_useragent()
        username = in_line_split[0].strip()
        password = in_line_split[1].strip()
        
        try_print('begin:', username)
        
        inst_checker_ctx = inst_checker.InstCheckerCtx()
        inst_checker.init_inst_checker_ctx(inst_checker_ctx, ua_name, username, password)
        safe_check(inst_checker_ctx)
        
        if inst_checker_ctx.error_type is not None:
            try_print('error:', inst_checker_ctx.error_type, inst_checker_ctx.error_str)
            continue
        
        if inst_checker_ctx.is_auth:
            out_good_fd.write('{}\n'.format(line))
            out_good_fd.flush()
        else:
            out_bad_fd.write('{}\n'.format(line))
            out_bad_fd.flush()
        
        try_print('result:', inst_checker_ctx.is_auth)
    
    try_print('all done!')
