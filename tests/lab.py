import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        path = urlsplit(self.path)
        account = "user-a" if self.headers.get("Cookie") == "sid=lab-user-a" else "user-b" if self.headers.get("Cookie") == "sid=lab-user-b" else "anonymous"
        status = 200
        self.server.hits.append((self.path, account))
        if path.path == "/api/me":
            data = {"id": account}
        elif path.path in ("/api/orders/1", "/api/orders/2"):
            # 1 is intentionally vulnerable, 2 enforces ownership.
            if path.path.endswith("/2") and account != "user-a":
                status, data = 403, {"error": "forbidden"}
            else:
                data = {"id": int(path.path.rsplit("/", 1)[1]), "owner": "user-a", "private": "lab-private-order"}
        elif path.path == "/api/orders/999":
            status, data = 404, {"error": "not found"}
        elif path.path == "/login-fallback":
            data = {"page": "login"}  # 200 must never become an auth finding.
        elif path.path == "/echo":
            data = {"q": parse_qs(path.query).get("q", [""])[0]}
        elif path.path == "/condition":
            data = {"result": "yes" if parse_qs(path.query).get("q") == ["true"] else "no"}
        elif path.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/api/orders/1")
            self.end_headers()
            return
        elif path.path == "/throttle":
            status, data = 429, {"error": "slow down"}
        else:
            status, data = 404, {"error": "not found"}
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def lab():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.hits = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def config_for(base):
    return {"origins": [base], "allow_private": True, "requests_per_second": 10000,
            "sessions": {"anonymous": {"headers_env": {}, "origins": []},
                         "user_a": {"origins": [base], "headers_env": {"Cookie": "LAB_COOKIE_A"},
                                    "health": {"url": base + "/api/me", "json_pointer": "/id", "equals": "user-a"}},
                         "user_b": {"origins": [base], "headers_env": {"Cookie": "LAB_COOKIE_B"},
                                    "health": {"url": base + "/api/me", "json_pointer": "/id", "equals": "user-b"}}}}
