import http.server
import sys


class ServerHandler(http.server.BaseHTTPRequestHandler):
    def _process_request(self):
        self.log_message("<<<HEADERS")
        self.log_message(self.headers.as_string().strip())
        self.log_message("HEADERS>>>")
        self.log_message("<<<BODY")
        try:
            content_length = int(self.headers['Content-Length'])
        except TypeError:
            self.log_message("ERROR: missing Content-Length")
        else:
            self.log_message(self.rfile.read(content_length).decode("utf-8"))
        self.log_message("BODY>>>")
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain;charset=utf-8')
        self.end_headers()
        self.wfile.write("OK\n".encode("utf-8"))

    def do_GET(self):
        self._process_request()

    def do_POST(self):
        self._process_request()


if __name__ == "__main__":
    try:
        port = int(sys.argv[1])
    except Exception:
        port = 8000
    server_address = ('', port)
    print("Starting server:", server_address)
    httpd = http.server.HTTPServer(server_address, ServerHandler)
    httpd.serve_forever()
