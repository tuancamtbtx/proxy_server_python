
# nguyen van tuan - vu anh linh
# import thread
import socket
import sys
import os
import datetime
import time
import threading
import string
import Queue


# import method get and post from lib methods
from methods.handle import method_get, method_post
from access.handle import get_access,leave_access
from cache_lib.handle import *
import config as cfg

logger = logging.getLogger('PROXY_SERVER')


# global variables
max_connections = cfg.max_connections


BUFFER_SIZE = cfg.BUFFER_SIZE
CACHE_DIR = cfg.CACHE_DIR
BLACKLIST_FILE = cfg.BLACKLIST_FILE
MAX_CACHE_BUFFER = cfg.MAX_CACHE_BUFFER
NO_OF_OCC_FOR_CACHE = cfg.NO_OF_OCC_FOR_CACHE


blocked = []
# default port server proxy 8888
PROXY_PORT = cfg.PROXY_PORT
PROXY_HOST = cfg.PROXY_HOST # <=> localhost

STATUS_CODE_RES = cfg.STATUS_CODE_RES


# read file black list to block client request if in blackl-list
# save black list  as globle var


#load menu PROXY SERVER
f = open('menu.txt', "rb")
while True:
    line = f.read()
    if not len(line):
        break
    print (line)
# close file
f.close()



file_black_list = open(BLACKLIST_FILE, "rb")
data = ""
while True:
    line = file_black_list.read()
    if not len(line):
        break
    data += line
# close file
file_black_list.close()
for file in os.listdir(CACHE_DIR):
    os.remove(CACHE_DIR + "/" + file)


def hexdump(src, length=16, sep='.'):
	DISPLAY = string.digits + string.letters + string.punctuation
	FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		if len(hex) > 24:
			hex = "%s %s" % (hex[:24], hex[24:])
		printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
		lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
	return ''.join(lines)

# source at https://www.geeksforgeeks.org/creating-a-proxy-webserver-in-python-set-1/
def convert_header(client_addr, client_data):
    try:
        # http://demo.unicore.asia/static/css/2.a2d88876.chunk.css
        if len (client_data) == 0:
            return None
        lines = client_data.splitlines()
        while lines[len(lines)-1] == '':
            lines.remove('')
        first_line_tokens = lines[0].split()
        print (first_line_tokens)
        # get url
        url = first_line_tokens[1]
        
        url_pos = url.find("://")
        if url_pos != -1:
            protocol = url[:url_pos]
            url = url[(url_pos+3):]
            
        else:
            protocol = "http"
        # get port if any
        # get url path
        port_pos = url.find(":")
        path_pos = url.find("/")
        if path_pos == -1:
            path_pos = len(url)
        # change request path accordingly
        if port_pos == -1 or path_pos < port_pos:
            server_port = 80
            server_url = url[:path_pos]
        else:
            server_port = int(url[(port_pos+1):path_pos])
            server_url = url[:port_pos]
        first_line_tokens[1] = url[path_pos:]
        lines[0] = ' '.join(first_line_tokens)
        client_data = "\r\n".join(lines) + '\r\n\r\n'
        return {
            "server_port" : server_port,
            "server_url" : server_url,
            "total_url" : url,
            "client_data" : client_data,
            "protocol" : protocol,
            "method" : first_line_tokens[0],
        }
    except Exception as e:
        error = str('convert_header_error:') + str(e)
        print "client_addr: %s %s %s" % (client_addr,error, client_data)
        pass


def save_header_modified(details):
    lines = details["client_data"].splitlines()
    while lines[len(lines) - 1] == '':
        lines.remove('')
    header = time.strftime("%a %b %d %H:%M:%S %Y", details["last_mtime"])
    header = "If-Modified-Since: " + header
    lines.append(header)
    details["client_data"] = "\r\n".join(lines) + "\r\n\r\n"
    return details

def check_blocked(blocked, details):
    if (details["server_url"]) in blocked: return True
    if not (details["server_url"] + ":" + str(details["server_port"])) in blocked:
        return False
    return True

def res_status_forbiden(client_socket):
    client_socket.send("HTTP/1.0 403 Forbidden \r\n")
    client_socket.send("Content-Length: 11\r\n")
    client_socket.send("\r\n")
    client_socket.send("<h1>403 Forbidden - ERROR </h1> Content-Type: text/html")
    client_socket.send("\r\n\r\n")

def handle_request_from_client(client_socket, client_addr, client_data):
    info_client = convert_header(client_addr, client_data)
    # print info_client
    if not info_client:
        client_socket.close()
        return
    black_lists = data
    is_blocked = check_blocked( black_lists, info_client)
    if is_blocked:
        res_status_forbiden(client_socket)
        client_socket.close()
        return
    if info_client["method"] == "CONNECT":
        client_socket.close()
        return
    if info_client["method"] == "GET":
        # check info cache of request from client
        info_client = get_cache_details(client_addr, info_client)
        if info_client["last_mtime"]:
            info_client = save_header_modified(info_client)
        method_get(client_socket, client_addr, info_client)
    if info_client["method"] == "POST":
        method_post(client_socket, client_addr, info_client)
    client_socket.close()


def proxy_start():
    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind((PROXY_HOST, PROXY_PORT))
        proxy_socket.listen(int(max_connections))
        sys.stdout.write("\033[1;36m")
        print ("[*] Init sockets ... Finished")
        print ("[*] Socket Binded successfully")
        print ("[*] Server Started On Port Successfully [%d] \n" % (PROXY_PORT))
        sys.stdout.write("\033[0;32m")
    except Exception as e:
        print ("Error in starting proxy server ...")
        logging.error(e)
        proxy_socket.close()
        sys.exit(2)
    # Main server loop
    while True:
        try:
            client_socket, client_addr = proxy_socket.accept()
            client_data = client_socket.recv(BUFFER_SIZE)
            while 1:
                t = threading.Thread(
                    target=handle_request_from_client,
                    args=(
                        client_socket,
                        client_addr,
                        client_data,
                    )
                )
                t.start()
         
        # exit processing
        except Exception as e:
            client_socket.close()
            proxy_socket.close()
            sys.stdout.write("\033[1;36m")
            print ("\n[Proxy server is existing :) ...]")
            sys.exit(1)
            break
    proxy_server.close()

logs = cfg.logs
locks = cfg.locks

proxy_start()