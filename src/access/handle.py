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
import config as cfg


logs = cfg.logs
locks = cfg.locks

def get_access(fileurl):
    if fileurl in locks:
        lock = locks[fileurl]
    else:
        lock = threading.Lock()
        locks[fileurl] = lock
    lock.acquire()

# unlock fileurl
def leave_access(fileurl):
    if fileurl in locks:
        lock = locks[fileurl]
        lock.release()
    else:
        print "Lock problem"
        sys.exit()
def add_log(fileurl, client_addr):
    fileurl = fileurl.replace("/", "__")
    if not fileurl in logs:
        logs[fileurl] = []
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")
    logs[fileurl].append({
            "datetime" : dt,
            "client" : json.dumps(client_addr),
        })
