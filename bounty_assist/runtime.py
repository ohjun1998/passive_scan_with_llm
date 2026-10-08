import copy
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .data import SECRET_KEY, Request, digest, origin


DEFAULTS = {"origins": [], "allow_private": False, "allowed_methods": ["GET", "HEAD"],
            "skip_path_pattern": r"(?i)(?:logout|signout|delete|remove|revoke|destroy|unsubscribe)",
            "max_requests": 200, "max_ai_calls": 12, "max_groups": 30,
            "rounds": 2, "max_plans_per_group": 3, "samples_per_group": 5,
            "max_body_bytes": 65536, "request_timeout": 10, "requests_per_second": 1,
            "evidence_ttl_seconds": 900,
            "max_model_tokens": 80000, "max_context_chars": 24000,
            "sessions": {"anonymous": {"origins": [], "headers_env": {}}}, "policies": [],
            "codex": {"executable": "codex", "model": "", "reasoning_effort": "low", "timeout": 180,
                      "adaptive_reasoning": False, "review_effort": "medium"}}


class BudgetExceeded(RuntimeError):
    pass


class Config:
    def __init__(self, data):
        self.data = copy.deepcopy(DEFAULTS)
        self.data.update(data)
        self.origins = {origin(x) for x in self.data["origins"]}
        if not self.origins:
            raise ValueError("origins must contain explicit authorized HTTP origins")
        for name in ("max_requests", "max_ai_calls", "max_groups", "rounds", "max_plans_per_group", "samples_per_group", "max_body_bytes", "evidence_ttl_seconds", "max_model_tokens", "max_context_chars"):
            value = self.data[name]
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("request_timeout", "requests_per_second"):
            if type(self.data[name]) not in (int, float) or self.data[name] <= 0:
                raise ValueError(f"{name} must be positive")
        if self.data["rounds"] > 5 or self.data["max_body_bytes"] > 1024 * 1024:
            raise ValueError("rounds <= 5; max_body_bytes <= 1 MiB")
        self.skip_path = re.compile(self.data["skip_path_pattern"])
        self.headers = {}
        self.session_origins = {}
        for name, session in self.data["sessions"].items():
            self.session_origins[name] = {origin(x) for x in session.get("origins", [])}
            if not self.session_origins[name].issubset(self.origins):
                raise ValueError(f"Session {name} origin is outside scope")
            headers = {}
            for header, env_name in session.get("headers_env", {}).items():
                if env_name not in os.environ or not os.environ[env_name]:
                    raise ValueError(f"Session {name}: required environment variable {env_name} is missing")
                if header.lower() in ("host", "content-length", "transfer-encoding", "connection", "accept-encoding"):
                    raise ValueError("Session cannot override transport headers")
                if "\r" in os.environ[env_name] or "\n" in os.environ[env_name]:
                    raise ValueError("Invalid session header")
                headers[header.lower()] = os.environ[env_name]
            if headers and not self.session_origins[name]:
                raise ValueError("Credentialed sessions must have explicit origins")
            if name == "anonymous" and headers:
                raise ValueError("anonymous must not contain credentials")
            self.headers[name] = headers
        if "anonymous" not in self.headers:
            raise ValueError("anonymous session is required")
        self.codex = {**DEFAULTS["codex"], **self.data.get("codex", {})}
        if self.codex["reasoning_effort"] not in ("low", "medium", "high"):
            raise ValueError("Unsupported reasoning effort")
        if type(self.codex["adaptive_reasoning"]) is not bool or self.codex["review_effort"] not in ("medium", "high"):
            raise ValueError("Unsupported adaptive reasoning configuration")
        if type(self.codex["timeout"]) not in (int, float) or not 1 <= self.codex["timeout"] <= 600:
            raise ValueError("Codex timeout must be between 1 and 600 seconds")
        if not 4000 <= self.data["max_context_chars"] <= 100000:
            raise ValueError("max_context_chars must be between 4000 and 100000")

    def secret_values(self):
        values = []
        for headers in self.headers.values():
            for key, value in headers.items():
                values.append(value)
                if key == "authorization" and " " in value:
                    values.append(value.split(" ", 1)[1])
                elif key == "cookie":
                    values.extend(part.split("=", 1)[1].strip() for part in value.split(";")
                                  if "=" in part and len(part.split("=", 1)[1].strip()) >= 8)
        return values

    def check(self, req, session):
        if origin(req.url) not in self.origins:
            raise ValueError("Request is outside configured origins")
        if session not in self.headers:
            raise ValueError("Unknown session")
        if self.headers[session] and origin(req.url) not in self.session_origins[session]:
            raise ValueError("Session credentials are not authorized for this origin")
        if req.method not in self.data["allowed_methods"]:
            raise ValueError("Method is not enabled in allowed_methods")
        if self.skip_path.search(unquote(req.url)):
            raise ValueError("URL excluded by skip_path_pattern")
        if not req.replayable:
            raise ValueError("Capture lacks replayable bytes (multipart/binary); manual test required")
        # Header sessions cannot safely switch credentials embedded in URL/body.
        if any(SECRET_KEY.search(k) for k, _ in parse_qsl(urlsplit(req.url).query, keep_blank_values=True)):
            raise ValueError("URL contains credentials; configure a clean request before replay")
        try:
            body = json.loads(req.body)
            def credential_keys(value):
                if isinstance(value, dict):
                    return any(SECRET_KEY.search(k) or credential_keys(v) for k, v in value.items())
                return isinstance(value, list) and any(credential_keys(v) for v in value)
            sensitive = credential_keys(body)
        except ValueError:
            sensitive = bool(re.search(r"(?i)(?:password|secret|token|session|api[-_]?key)\s*(?:=|>|[\"']?\s*:)", req.body))
        if sensitive:
            raise ValueError("Body credentials/CSRF refresh need a dedicated adapter; manual test required")


def pointer(value, path):
    if path == "":
        return value
    if not path.startswith("/"):
        raise ValueError("JSON field must use a JSON Pointer")
    for component in path[1:].split("/"):
        key = component.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def mutate(req, location, field, value):
    result = copy.deepcopy(req)
    if len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError("Mutation must be <= 256 printable characters")
    if SECRET_KEY.search(field):
        raise ValueError("Credential fields cannot be mutated")
    if location in ("query", "form"):
        p = urlsplit(result.url)
        if location == "form" and not result.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            raise ValueError("Not a form request")
        values = parse_qsl(p.query if location == "query" else result.body, keep_blank_values=True)
        if field not in [k for k, _ in values]:
            raise ValueError("Mutation field must exist")
        values = [(k, value if k == field else v) for k, v in values]
        if location == "query":
            result.url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(values), ""))
        else:
            result.body = urlencode(values)
    elif location == "json":
        body = json.loads(result.body)
        if not field.startswith("/") or field == "/":
            raise ValueError("JSON mutation requires a non-root pointer")
        parent_path, _, key = field.rpartition("/")
        parent = pointer(body, parent_path)
        key = key.replace("~1", "/").replace("~0", "~")
        pointer(body, field)  # Refuse new keys.
        if isinstance(parent, list):
            parent[int(key)] = value
        else:
            parent[key] = value
        result.body = json.dumps(body)
    elif location == "path":
        # Only replace one existing segment; never introduce another path/host.
        p = urlsplit(result.url)
        parts = p.path.split("/")
        index = int(field)
        if index <= 0 or index >= len(parts) or not parts[index]:
            raise ValueError("Invalid path segment index")
        if value in ("", ".", "..") or any(c in value for c in "/\\%?#"):
            raise ValueError("Path mutation must be one literal segment")
        parts[index] = quote(value, safe="")
        result.url = urlunsplit((p.scheme, p.netloc, "/".join(parts), p.query, ""))
    else:
        raise ValueError("Unsupported mutation location")
    return result


class Transport:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.last_request = 0.0

    def send(self, req, session):
        self.config.check(req, session)
        p = urlsplit(req.url)
        port = p.port or (443 if p.scheme == "https" else 80)
        addresses = sorted({a[4][0] for a in socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)})
        if not addresses:
            raise ValueError("No DNS addresses")
        if not self.config.data["allow_private"] and any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError("Non-public DNS address blocked; lab requires allow_private=true")
        if not self.store.reserve("http_requests", self.config.data["max_requests"]):
            raise BudgetExceeded("HTTP request budget exhausted")
        delay = self.last_request + 1 / self.config.data["requests_per_second"] - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.last_request = time.monotonic()
        timeout = self.config.data["request_timeout"]
        conn = (http.client.HTTPSConnection(p.hostname, port, timeout=timeout, context=ssl.create_default_context())
                if p.scheme == "https" else http.client.HTTPConnection(p.hostname, port, timeout=timeout))
        # Resolve once, pin the connection, preserve Host and TLS hostname validation.
        def connect():
            conn.sock = socket.create_connection((addresses[0], port), timeout)
            if p.scheme == "https":
                conn.sock = conn._context.wrap_socket(conn.sock, server_hostname=p.hostname)
        conn.connect = connect
        blocked = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding", "proxy-authorization"}
        headers = {k: v for k, v in req.headers.items() if k not in blocked and not k.startswith(":")}
        headers.update(self.config.headers[session])
        headers["accept-encoding"] = "identity"
        headers.setdefault("user-agent", "passive-scan-bounty-assist/0.1")
        started = time.monotonic()
        try:
            conn.request(req.method, (p.path or "/") + ("?" + p.query if p.query else ""),
                         req.body.encode() if req.body else None, headers)
            response = conn.getresponse()
            limit = self.config.data["max_body_bytes"]
            raw = response.read(limit + 1)
            encoding = response.getheader("Content-Encoding", "identity").lower()
            # Unexpected compression is recorded, not mistaken for readable evidence.
            truncated = len(raw) > limit
            body = raw[:limit].decode("utf-8", errors="replace") if encoding in ("", "identity") else "[compressed response; manual decoding required]"
            return {"status": response.status, "headers": dict(response.getheaders()), "body": body,
                    "truncated": truncated, "unreadable": encoding not in ("", "identity"),
                    "elapsed_ms": round((time.monotonic() - started) * 1000), "sha256": digest(body),
                    "redirect_followed": False}
        finally:
            conn.close()
