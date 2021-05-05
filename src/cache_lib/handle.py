
# nguyen van tuan - vu anh linh
import base64
import copy
import thread
import socket
import sys
import os
import datetime
import time
import json
import threading

import logging
# import method get and post from lib methods
from access.handle import get_access,leave_access
import config as cfg
from color_log.ColorizePython import *
# global variables
max_connections = 10
BUFFER_SIZE = 4096

CACHE_DIR = "cache_data"
BLACKLIST_FILE = "blacklist.conf"
MAX_CACHE_BUFFER = 3
NO_OF_OCC_FOR_CACHE = 2
blocked = []
# default port server proxy 8888
PROXY_PORT = 8888
PROXY_HOST = '127.0.0.1' # <=> localhost

RESPONSE_CODES = {
    200: 'OK',
    304: 'Not Modified',
    400: 'Bad Request',
    404: 'Not Found',
    403: 'Forbiden',
    405: 'Method Not Allowed',
    414: 'Request URI too long',
}
logs = cfg.logs
locks = cfg.locks
def to_seconds(date):
    return time.mktime(date.timetuple())

def add_log(fileurl, client_addr):
    fileurl = fileurl.replace("/", "__")
    if not fileurl in logs:
        logs[fileurl] = []
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")
    logs[fileurl].append({
            "datetime" : dt,
            "client" : json.dumps(client_addr),
        })

def do_cache_or_not(fileurl):
    try:
        log_arr = logs[fileurl.replace("/", "__")]
        if len(log_arr) < NO_OF_OCC_FOR_CACHE : return False
        last_third = log_arr[len(log_arr)-NO_OF_OCC_FOR_CACHE]["datetime"]
        if datetime.datetime.fromtimestamp(time.mktime(last_third)) + datetime.timedelta(minutes=10) >= datetime.datetime.now():
            return True
        else:
            return False
    except Exception as e:
        print e
        return False
def get_current_cache_info(fileurl):
    if fileurl.startswith("/"):
        fileurl = fileurl.replace("/", "", 1)
    cache_path = CACHE_DIR + "/" + fileurl.replace("/", "__")
    if os.path.isfile(cache_path):
        last_mtime = time.strptime(time.ctime(os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
        return cache_path, last_mtime
    else:
        return cache_path, None


# collect all cache info
def get_cache_details(client_addr, details):
    get_access(details["total_url"])
    add_log(details["total_url"], client_addr)
    do_cache = do_cache_or_not(details["total_url"])
    cache_path, last_mtime = get_current_cache_info(details["total_url"])
    leave_access(details["total_url"])
    details["do_cache"] = do_cache
    details["cache_path"] = cache_path
    details["last_mtime"] = last_mtime
    return details


# if cache is full then delete the least recently used cache item
def get_space_for_cache(fileurl):
    cache_files = os.listdir(CACHE_DIR)
    if len(cache_files) < MAX_CACHE_BUFFER:
        return
    for file in cache_files:
        get_access(file)
    last_mtime = min(logs[file][-1]["datetime"] for file in cache_files)
    file_to_del = [file for file in cache_files if logs[file][-1]["datetime"] == last_mtime][0]
    os.remove(CACHE_DIR + "/" + file_to_del)
    for file in cache_files:
        leave_access(file)

