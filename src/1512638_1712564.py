#!/usr/bin/env python
# -*- coding: utf-8 -*-
import errno
import base64
import socket
import select
import logging
import argparse
import datetime



import os
import sys

import threading
from collections import namedtuple


if os.name != 'nt':
    import resource


#get black list
BLACKLIST_FILE = "blacklist.conf"
BUFFER_SIZE = 8192


#  check black list ,which block host
def check_blocked(blocked, url):
    if url in blocked: return True
    return False

# read file blacklist.conf
file_black_list = open(BLACKLIST_FILE, "rb")
black_list = ""
while True:
    line = file_black_list.read()
    if not len(line):
        break
    black_list += str(line)
# close file
file_black_list.close()

python_version = sys.version_info[0]

if python_version == 3:    # pragma: no cover
    text_type = str
    binary_type = bytes
    from urllib import parse as urlparse
else:   # pragma: no cover
    text_type = unicode
    binary_type = str
    import urlparse



# Bytes literals are always prefixed with 
# 'b' or 'B'; they produce an instance of the bytes type instead of the str type. They may only contain ASCII characters; 
# bytes with a numeric value of 128 or greater must be expressed with escapes.
RN = B'\r\n'
COLON = B':'
SPACE = B' '

# set version
version = b'v1.0.0'
PROXY_AGENT_HEADER = b'Proxy-agent: hcmus_mmt_3864 '+ version

HOST_ADDRESS= '127.0.0.1'
PORT_SERVER = 8888

CONTENT_FORBIDDEN = '<div style="border-style: solid;border-width: 2px 2px 5px 2px;text-align: center";text-align:center;"><p style="font-size:40px;font-weight:700;">Forbidden 403</p></br> <p style="font-size:24px;">You don not have permission/ on this server</p><span>Blocked by TuanLinh-proxy</span></div>'
CONTENT_BAD_REQUEST = '<h1>Bad Gateway</h1>'


FORBIDDEN_REPSONSE = RN.join([
    b'HTTP/1.1 403 Forbidden',
    PROXY_AGENT_HEADER,
    b'Content-Length:' + bytes(str(len(CONTENT_FORBIDDEN)), encoding='utf-8'),
    b'Connection: close',
    RN
]) + bytes(CONTENT_FORBIDDEN,encoding='utf-8')


PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = RN.join([
    b'HTTP/1.1 200 Connection established',
    PROXY_AGENT_HEADER,
    RN
])

BAD_GATEWAY_RESPONSE = RN.join([
    b'HTTP/1.1 502 Bad Gateway',
    PROXY_AGENT_HEADER,
    b'Content-Length:' + bytes(str(len(CONTENT_BAD_REQUEST)),encoding='utf-8'),
    b'Connection: close',
    RN
]) + bytes(CONTENT_BAD_REQUEST, encoding='utf-8')


# block web and repqnse forbident

class Forbidden(Exception):
    pass

class ProxyError(Exception):
    pass

class ProxyConnectionFailed(ProxyError):

    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason

    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)

class ProxyAuthenticationFailed(ProxyError):
    pass



# copy at https://github.com/abhinavsingh/proxy.py/blob/develop/proxy.py - tuancam 1/6/2019
class DataParser(object):

    states = namedtuple('ChunkParserStates', (
        'WAITING_FOR_SIZE',
        'WAITING_FOR_DATA',
        'COMPLETE'
    ))(1, 2, 3)

    def __init__(self):
        self.state = DataParser.states.WAITING_FOR_SIZE
        self.body = b''     
        self.chunk = b''    
        self.size = None    

    def parse(self, data):
        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)

    def process(self, data):
        if self.state == DataParser.states.WAITING_FOR_SIZE:
            data = self.chunk + data
            self.chunk = b''
            line, data = HttpParser.split(data)
            if not line:    
                self.chunk = data
                data = b''
            else:
                self.size = int(line, 16)
                self.state = DataParser.states.WAITING_FOR_DATA
        elif self.state == DataParser.states.WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(RN):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = DataParser.states.COMPLETE
                else:
                    self.state = DataParser.states.WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(data) > 0, data




class HttpParser(object):

    states = namedtuple('HttpParserStates', (
        'INITIALIZED',
        'LINE_RCVD',
        'RCVING_HEADERS',
        'HEADERS_COMPLETE',
        'RCVING_BODY',
        'COMPLETE'))(1, 2, 3, 4, 5, 6)

    types = namedtuple('HttpParserTypes', (
        'REQUEST_PARSER',
        'RESPONSE_PARSER'
    ))(1, 2)

    def __init__(self, parser_type):
        assert parser_type in (HttpParser.types.REQUEST_PARSER, HttpParser.types.RESPONSE_PARSER)
        self.type = parser_type
        self.state = HttpParser.states.INITIALIZED

        self.raw = b''
        self.buffer = b''

        self.headers = dict()
        self.body = None
        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

        self.chunk_parser = None

    def is_chunked_encoded_response(self):
        return self.type == HttpParser.types.RESPONSE_PARSER and \
            b'transfer-encoding' in self.headers and \
            self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = b''

        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)
        self.buffer = data

    def process(self, data):
        if self.state in (HttpParser.states.HEADERS_COMPLETE,
                          HttpParser.states.RCVING_BODY,
                          HttpParser.states.COMPLETE) and \
                (self.method == b'POST' or self.type == HttpParser.types.RESPONSE_PARSER):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HttpParser.states.RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HttpParser.states.COMPLETE
            elif self.is_chunked_encoded_response():
                if not self.chunk_parser:
                    self.chunk_parser = DataParser()
                self.chunk_parser.parse(data)
                if self.chunk_parser.state == DataParser.states.COMPLETE:
                    self.body = self.chunk_parser.body
                    self.state = HttpParser.states.COMPLETE
            return False, b''

        line, data = HttpParser.split(data)
        if line is False:
            return line, data

        if self.state == HttpParser.states.INITIALIZED:
            self.process_line(line)
        elif self.state in (HttpParser.states.LINE_RCVD, HttpParser.states.RCVING_HEADERS):
            self.process_header(line)

        if self.state == HttpParser.states.LINE_RCVD and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'CONNECT' and \
                data == RN:
            self.state = HttpParser.states.COMPLETE

        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method != b'POST' and \
                self.raw.endswith(RN * 2):
            self.state = HttpParser.states.COMPLETE
        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'POST' and \
                (b'content-length' not in self.headers or
                 (b'content-length' in self.headers and
                  int(self.headers[b'content-length'][1]) == 0)) and \
                self.raw.endswith(RN * 2):
            self.state = HttpParser.states.COMPLETE

        return len(data) > 0, data

    def process_line(self, data):
        line = data.split(SPACE)
        if self.type == HttpParser.types.REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self.state = HttpParser.states.LINE_RCVD

    def process_header(self, data):
        if len(data) == 0:
            if self.state == HttpParser.states.RCVING_HEADERS:
                self.state = HttpParser.states.HEADERS_COMPLETE
            elif self.state == HttpParser.states.LINE_RCVD:
                self.state = HttpParser.states.RCVING_HEADERS
        else:
            self.state = HttpParser.states.RCVING_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)

    def convert_url(self):
        if not self.url:
            return b'/None'

        url = self.url.path
        if url == b'':
            url = b'/'
        if not self.url.query == b'':
            url += b'?' + self.url.query
        if not self.url.fragment == b'':
            url += b'#' + self.url.fragment
        return url

    def build(self, del_headers=None, add_headers=None):
        req = b' '.join([self.method, self.convert_url(), self.version])
        req += RN
        if not del_headers:
            del_headers = []
        for k in self.headers:
            if k not in del_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1]) + RN

        if not add_headers:
            add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1]) + RN

        req += RN
        if self.body:
            req += self.body

        return req

    @staticmethod
    def build_header(k, v):
        return k + b': ' + v

    @staticmethod
    def split(data):
        pos = data.find(RN)
        if pos == -1:
            return False, data
        line = data[:pos]
        data = data[pos + len(RN):]
        return line, data

class Connection(object):

    def __init__(self, what):
        self.conn = None
        self.buffer = b''
        self.closed = False
        self.what = what  # server connection or client connection

    def send_data(self, data):
        return self.conn.send(data)
#   receive
    def receive_data(self, bufsiz=8192):
        try:
            data = self.conn.recv(bufsiz)
            if len(data) == 0:
                return None
            return data
        except Exception as e:
            if e.errno == errno.ECONNRESET:
                print('%r' % e)
            else:
                print(
                    'Exception while receiving from connection %s %r with reason %r' % (self.what, self.conn, e))
            return None

    def close(self):
        self.conn.close()
        self.closed = True

    def buffer_size(self):
        return len(self.buffer)

    def has_buffer(self):
        return self.buffer_size() > 0

    def add(self, data):
        self.buffer += data

    def flush(self):
        sent = self.send_data(self.buffer)
        self.buffer = self.buffer[sent:]



class Server(Connection):
    def __init__(self, host, port):
        super(Server, self).__init__(b'server')
        self.addr = (host, int(port))

    def __del__(self):
        if self.conn:
            self.close()

    def connect(self):
        self.conn = socket.create_connection((self.addr[0], self.addr[1]))


class Client(Connection):
    def __init__(self, conn, addr):
        super(Client, self).__init__(b'client')
        self.conn = conn
        self.addr = addr


class TCP_SERVER(object):

    def __init__(self, hostname=HOST_ADDRESS, port=PORT_SERVER, backlog=100):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog
        self.socket = None
    def handle(self, client):
        raise NotImplementedError()

    def run(self):
        try:
            sys.stdout.write("\033[1;36m")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(self.backlog)
            print ("[*] Init sockets ... Finished")
            print ("[*] Socket Binded successfully")
            print ("[*] Server Started On Port Successfully [%d] \n" % (self.port))
            sys.stdout.write("\033[0;32m")
            while True:
                conn, addr = self.socket.accept()
                client = Client(conn, addr)
                self.handle(client)
        except Exception as e:
            print (e)
        finally:
            print('Closing server socket')
            self.socket.close()


class ProxyServer(threading.Thread):
   
    def __init__(self, client, server_recvbuf_size=BUFFER_SIZE, client_recvbuf_size=BUFFER_SIZE):
        super(ProxyServer, self).__init__()
        self.start_time = datetime.datetime.utcnow()
        self.last_activity = self.start_time

        #INIT START CLIENT SERVER
        self.client = client
        self.client_recvbuf_size = client_recvbuf_size

        # INIT SERVER
        self.server = None
        self.server_recvbuf_size = server_recvbuf_size
        # request data
        self.request = HttpParser(HttpParser.types.REQUEST_PARSER)
        # reponse data
        self.response = HttpParser(HttpParser.types.RESPONSE_PARSER)

    @staticmethod
    def is_inactive(self):
        return (datetime.datetime.utcnow() - self.last_activity).seconds > 30


    # handle request from client catch 403 stattus bad gateway 502
    # check method CONNECT - of browser
    # send data to server
    def handle_request_from_client(self, data):
  
        if self.server and not self.server.closed:
            self.server.add(data)
            return
        self.request.parse(data)
        if check_blocked(black_list, self.request.url.hostname.decode("utf-8")) == True:
            self.client.add(FORBIDDEN_REPSONSE)
            raise Exception('Forbidden 403' )
        if self.request.state == HttpParser.states.COMPLETE:
            if self.request.method == b'CONNECT':
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80
            else:
                raise Exception('Invalid request\n%s' % self.request.raw)
            
            self.server = Server(host, port)
            try:
                self.server.connect()
            except Exception as e:  # TimeoutError, socket.gaierror, 403 forbidden
                self.server.closed = True
                raise ProxyConnectionFailed(host, port, repr(e))

            if self.request.method == b'CONNECT':
                self.client.add(PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
            else:
                self.server.add(self.request.build(
                    del_headers=[b'proxy-authorization', b'proxy-connection', b'connection', b'keep-alive'],
                    add_headers=[(b'Via', b'1.1 proxy.py v%s' % version), (b'Connection', b'Close')]
                ))
            
    def handle_response(self, data):
        if not self.request.method == b'CONNECT':
            self.response.parse(data)
        self.client.add(data)


    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.conn], [], []
        if self.client.has_buffer():
            wlist.append(self.client.conn)
        if self.server and not self.server.closed:
            rlist.append(self.server.conn)
        if self.server and not self.server.closed and self.server.has_buffer():
            wlist.append(self.server.conn)
        return rlist, wlist, xlist

    def _process_wlist(self, w):
        if self.client.conn in w:
            self.client.flush()

        if self.server and not self.server.closed and self.server.conn in w:
            self.server.flush()

    def _process_rlist(self, r):
        if self.client.conn in r:
            data = self.client.receive_data(self.client_recvbuf_size)
            self.last_activity = datetime.datetime.utcnow()
            if not data:
                return True

            try:
                return self.handle_request_from_client(data)
            except Exception as e:
                print(e)
                self.client.add(BAD_GATEWAY_RESPONSE)
                self.client.flush()
                return True
        if self.server and not self.server.closed and self.server.conn in r:
            data = self.server.receive_data(self.server_recvbuf_size)
            self.last_activity = datetime.datetime.utcnow()
            if not data:
                self.server.close()
            else:
                self.handle_response(data)

        return False

    def processing(self):
        while True:
            rlist, wlist, xlist = self._get_waitable_lists()
            r, w, x = select.select(rlist, wlist, xlist, 1)
            self._process_wlist(w)
            if self._process_rlist(r):
                break
            if self.client.buffer_size() == 0:
                if self.response.state == HttpParser.states.COMPLETE:
                    break
                if self.is_inactive(self):
                    break
    def run(self):
        try:
            self.processing()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print (e)
        finally:
            self.client.close()
            # if self.server:
            print('Closing proxy for connection %r at address %r' % (self.client.conn, self.client.addr))



class HTTP_PROTOCOL(TCP_SERVER):

    def __init__(self, hostname=HOST_ADDRESS, port=PORT_SERVER, backlog=100,
                  server_recvbuf_size=8192, client_recvbuf_size=8192):
        super(HTTP_PROTOCOL, self).__init__(hostname, port, backlog)
        self.client_recvbuf_size = client_recvbuf_size
        self.server_recvbuf_size = server_recvbuf_size

    def handle(self, client):
        proxy = ProxyServer(client,
                      server_recvbuf_size=self.server_recvbuf_size,
                      client_recvbuf_size=self.client_recvbuf_size,
                      )
        proxy.daemon = True
        proxy.start()


def main():
    proxy = HTTP_PROTOCOL(hostname=HOST_ADDRESS,
                     port=int(PORT_SERVER),
                     backlog=100,
                     server_recvbuf_size=BUFFER_SIZE,
                     client_recvbuf_size=BUFFER_SIZE,
                     )
    proxy.run()

if __name__ == '__main__':
    main()