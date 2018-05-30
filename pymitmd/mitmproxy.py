from http.server import BaseHTTPRequestHandler
import http.client as httpclient
import ssl
from urllib.parse import urlparse
import threading


class MitmProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_addr, server):
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

        u = urlparse.urlsplit(self.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        newHeaders = self.filter_headers(self.headers)

        try:
            conn = ''
            if scheme == 'https':
                conn = httpclient.HTTPSConnection(netloc, timeout=5)
            else:
                conn = httpclient.HTTPConnection(netloc, timeout=5)

            conn.request(self.command, path, reqBody, dict(newHeaders))
            res = conn.getresponse()
            resBody = res.read()

        except Exception as e:
            pass

    
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