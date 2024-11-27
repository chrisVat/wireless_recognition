import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class TimeSyncHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sync_time':
            # Get the server's current time in milliseconds
            server_time = int(time.time() * 1000)
            
            # Log the time sync request to the console
            print(f"Time sync request received. Server time: {server_time} ms")
            
            # Send back the server time as a JSON response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = f'{{"server_time": {server_time}}}'
            self.wfile.write(response.encode('utf-8'))
        else:
            # For other requests, serve the default files (like index.html)
            super().do_GET()

    def do_POST(self):
        # Parse the request URL to extract the time difference sent by the client
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/report_time_diff':
            # Extract the time difference from the query parameters
            query = parse_qs(parsed_path.query)
            time_diff = query.get('diff', [None])[0]
            if time_diff:
                print(f"Time difference received from client: {time_diff} ms")
            
            # Send a basic response to confirm receipt
            self.send_response(200)
            self.end_headers()
        if parsed_path.path == '/report_final_time_diff':
            # Extract the time difference from the query parameters
            query = parse_qs(parsed_path.query)
            time_diff = query.get('diff', [None])[0]
            if time_diff:
                print(f"FINAL DIFFERENCE (server-client): {time_diff}")
            
            # Send a basic response to confirm receipt
            self.send_response(200)
            self.end_headers()

# Set up the HTTP server
def run(server_class=HTTPServer, handler_class=TimeSyncHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting time sync server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
