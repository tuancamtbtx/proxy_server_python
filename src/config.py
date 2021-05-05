max_connections = 50
BUFFER_SIZE = 999999 #10 MB
CACHE_DIR = "./cache_data"
BLACKLIST_FILE = "blacklist.conf"
MAX_CACHE_BUFFER = 3
NO_OF_OCC_FOR_CACHE = 2
blocked = []
# default port server proxy 8888
PROXY_PORT = 8888
PROXY_HOST = '127.0.0.1' # <=> localhost

STATUS_CODE_RES = {
    200: 'OK',
    304: 'Not Modified',
    400: 'Bad Request',
    404: 'Not Found',
    403: 'Forbiden',
    405: 'Method Not Allowed',
    414: 'Request URI too long',
}

logs = {}
locks = {}