import http
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

port = 8080

NECURS_URI = {
    "/locator.php": 0x5ba4fa79,
    "/forum/db.php": 0x36bb6083
}



fn = "/mnt/malware/wanameil/server0"
class NecursHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path in NECURS_URI:
            httpReqBody = self.rfile.read(int(self.headers['Content-Length']))
            c = necurs.http.clientMsg() 
            c.setBaseSeed(NECURS_URI[httpReq.uri])
            c.parse(httpReqBody)


            """
            self.send_response(200)
            self.send_header('Server','nginx')
            self.send_header('Content-Length',len(respData))
            self.end_headers()
            self.wfile.write(respData)
            """
        else:
            print self.path

def main():
    try:
        server = HTTPServer(("", port), NecursHandler)
        print "Listening on port ", port
        server.serve_forever()

    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()