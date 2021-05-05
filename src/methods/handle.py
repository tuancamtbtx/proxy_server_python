# handle METHODS from client requests

# import thread
import socket
import sys
import os
import datetime
import time
import threading
import config as cfg
from access.handle import get_access,leave_access
from cache_lib.handle import *


BUFFER_SIZE = cfg.BUFFER_SIZE
CACHE_DIR = cfg.CACHE_DIR

def check_file_cache_data(cache_path):
    if not cache_path:
        return False
    check = os.path.isfile(cache_path)
    return check
    # print check   # True  


def method_get(client_socket, client_addr, details):
    try:
        client_data = details["client_data"]
        do_cache = details["do_cache"]
        cache_path = details["cache_path"]
        last_mtime = details["last_mtime"]
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((details["server_url"], details["server_port"]))
        server_socket.send(details["client_data"])
        reply = server_socket.recv(BUFFER_SIZE)
        check = check_file_cache_data(cache_path)
        # check file cached file  status 304 is get cache to read and load 
        if last_mtime and check == False:
            print ("[*]get cache file from %s to %s" % (cache_path, str(client_addr)))               
            get_access(details["total_url"])
            f = open(cache_path, 'rb')
            chunk = f.read(BUFFER_SIZE)
            while chunk:
                client_socket.send(chunk)
                chunk = f.read(BUFFER_SIZE)
            f.close()
            leave_access(details["total_url"])
        else:
            if do_cache:
                print ("[*]caching file while serving %s to %s" % (cache_path, str(client_addr)))
                print ('\n')               
                get_space_for_cache(details["total_url"])
                get_access(details["total_url"])
                f = open(cache_path, "w+")
                while len(reply):
                    client_socket.send(reply)
                    f.write(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                f.close()
                leave_access(details["total_url"])
                client_socket.send("\r\n\r\n")
            else:
                print ('[*]send data without cache')
                while len(reply):
                    client_socket.send(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                client_socket.send("\r\n\r\n")     
        server_socket.close()
        client_socket.close()
        return
    except Exception as e:
        print ('handle_method_GET_error:')
        print (e)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.close()
        client_socket.close()
        return

def method_post(client_socket, client_addr, details):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((details["server_url"], details["server_port"]))
        server_socket.send(details["client_data"])
        while True:
            reply = server_socket.recv(BUFFER_SIZE)
            if len(reply):
                client_socket.send(reply)
            else:
                break
        server_socket.close()
        client_socket.close()
        return

    except Exception as e:
        print e
        server_socket.close()
        client_socket.close()
        return