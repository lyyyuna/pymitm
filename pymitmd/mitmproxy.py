from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client as httpclient
from socketserver import ThreadingMixIn
import ssl
from urllib.parse import urlparse, urlsplit
import threading
import logging
import io, socket, sys
import gzip
import zlib

from concurrent.futures import ThreadPoolExecutor # pip install futures


class PoolMixIn(ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)


class ThreadingHTTPServer(PoolMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    pool = ThreadPoolExecutor(max_workers=40)

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class MitmProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_addr, server):
        self.logger = logging.getLogger('pymitmd')
        BaseHTTPRequestHandler.__init__(self, request, client_addr, server)

    def do_GET(self):
        contentLen = int(self.headers.get('Content-Length', 0))
        reqBody = self.rfile.read(content_length) if contentLen else None

        # 有时候浏览器在代理状态下，仍旧发送相对路径
        # 这里转换为全路径
        # sometimes browser send relative path
        # convert to absolute path
        if self.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                self.path = "https://{0}{1}".format(self.headers['Host'], self.path)
            else:
                self.path = "https://{0}{1}".format(self.headers['Host'], self.path)

        u = urlsplit(self.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        newHeaders = self.filter_headers(self.headers)

        res = ''
        try:
            conn = ''
            if scheme == 'https':
                conn = httpclient.HTTPSConnection(netloc, timeout=5)
            else:
                conn = httpclient.HTTPConnection(netloc, timeout=5)

            conn.request(self.command, path, reqBody, dict(newHeaders))
            res = conn.getresponse()
            resBody = res.read()
            # self.logger.info(resBody)
        except Exception as e:
            self.logger.error(e)
            self.send_error(502)
            return

        contentEncoding = res.headers.get('Content-Encoding', 'identity')
        resBodyPlain = self.decodeContent(resBody, contentEncoding)

        self.wfile.write("{0} {1} {2}\r\n".format('HTTP/1.1', res.status, res.reason).encode())
        self.wfile.write(str(res.headers).encode())
        self.wfile.write(resBody)
        self.wfile.flush()

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        blacllist = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade', 'Accept-Encoding')
        for key in blacllist:
            del headers[key]

        # accept only supported encodings
        # if 'Accept-Encoding' in headers:
        #    ae = headers['Accept-Encoding']
        #    filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
        #    headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers        

    def decodeContent(self, data, encoding):
        if encoding == 'identity':
            return data
        elif encoding in ('gzip', 'x-gzip'):
            io = io.StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                return f.read()
        elif encoding == 'deflate':
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            pass

    def do_CONNECT(self):
        hostname = self.path.split(':')[0]

        from certauth.certauth import CertificateAuthority
        ca = CertificateAuthority('My Custom CA', 'ca/certs/ca.pem', cert_cache='tmp/certs')
        filename = ca.cert_for_host(hostname)

        self.wfile.write("{0} {1} {2}\r\n\r\n".format('HTTP/1.1', 200, 'Connection Established').encode())
        self.wfile.flush()

        self.connection = ssl.wrap_socket(self.connection, keyfile=filename, certfile=filename, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1


def test():
    from logging.config import fileConfig

    fileConfig('logging_config.ini')

    httpd = ThreadingHTTPServer(('0.0.0.0', 8011), MitmProxyHandler)
    httpd.serve_forever()


if __name__ == '__main__':
    test()