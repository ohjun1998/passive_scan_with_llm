import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SECRET_KEY = re.compile(r"(?:authorization|cookie|password|passwd|pwd|secret|token|api[-_]?key|csrf|xsrf|session|credential)", re.I)
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
STATIC = (".png", ".jpg", ".jpeg", ".gif", ".css", ".woff", ".woff2", ".ico", ".mp4")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def origin(url):
    p = urlsplit(url)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username is not None
            or p.password is not None or any(ord(c) <= 32 for c in url)):
        raise ValueError("Invalid HTTP URL (credentials/control characters forbidden)")
    host = p.hostname.lower().encode("idna").decode()
    port = p.port or (443 if p.scheme == "https" else 80)
    rendered = f"[{host}]" if ":" in host else host
    return f"{p.scheme}://{rendered}:{port}"


def canonical_url(url):
    origin(url)
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def path_template(path):
    return "/".join("{id}" if s.isdecimal() else "{uuid}" if UUID.fullmatch(s) else s for s in path.split("/"))


def shape(value):
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted({json.dumps(shape(v), sort_keys=True) for v in value})
    return type(value).__name__


@dataclass
class Request:
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    session: str = "anonymous"
    owner: str = ""
    source: str = "url-list"
    replayable: bool = True

    def __post_init__(self):
        self.url = canonical_url(self.url)
        self.method = self.method.upper()
        # Captured credentials never become another account's replay headers.
        self.headers = {k.lower(): str(v) for k, v in self.headers.items() if not SECRET_KEY.search(k)}

    @property
    def id(self):
        identity = asdict(self)
        identity.pop("source")  # Different collector files must not duplicate the same request.
        return digest(identity)[:24]

    @property
    def group(self):
        p = urlsplit(self.url)
        content_type = self.headers.get("content-type", "").split(";")[0]
        try:
            body_shape = shape(json.loads(self.body)) if self.body else ""
        except (ValueError, TypeError):
            body_shape = sorted(k for k, _ in parse_qsl(self.body)) if content_type == "application/x-www-form-urlencoded" else content_type
        return digest([origin(self.url), self.method, path_template(p.path),
                       sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)), content_type, body_shape])[:24]

    @property
    def priority(self):
        text = urlsplit(self.url).path.lower()
        score = 0
        for word, weight in (("admin", 6), ("order", 5), ("account", 5), ("file", 4),
                             ("upload", 4), ("invoice", 5), ("auth", 4), ("api", 2)):
            if word in text:
                score += weight
        if "{id}" in path_template(text) or urlsplit(self.url).query:
            score += 4
        if self.method != "GET":
            score += 2
        if text.endswith(STATIC):
            score -= 20
        return score


class Redactor:
    """Best-effort masking, not a DLP guarantee. Raw captures remain local."""
    def __init__(self, salt, secrets=()):
        self.salt = salt
        self.secrets = sorted({str(s) for s in secrets if s}, key=len, reverse=True)

    def alias(self, value):
        return "[masked:" + hmac.new(self.salt, str(value).encode(), "sha256").hexdigest()[:12] + "]"

    def text(self, value):
        value = str(value)
        for secret in self.secrets:
            value = value.replace(secret, self.alias(secret))
        value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", lambda m: self.alias(m[0]), value)
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", lambda m: self.alias(m[0]), value)
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", lambda m: m[1] + self.alias(m[0]), value)
        value = re.sub(r"(?i)((?:password|secret|token|api[_-]?key|session)[\w-]*[\"']?\s*[:=]\s*[\"']?)([^\s\"'<>&,}]+)",
                       lambda m: m[1] + self.alias(m[2]), value)
        value = re.sub(r"(?is)(<([\w:.-]*(?:password|secret|token|session)[\w:.-]*)[^>]*>)(.*?)(</\2\s*>)",
                       lambda m: m[1] + self.alias(m[3]) + m[4], value)
        return value

    def obj(self, value):
        if isinstance(value, dict):
            return {k: self.alias(v) if SECRET_KEY.search(k) else self.obj(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        return self.text(value) if isinstance(value, str) else value

    def url(self, value):
        p = urlsplit(value)
        query = [(k, self.alias(v) if SECRET_KEY.search(k) else self.text(v)) for k, v in parse_qsl(p.query, keep_blank_values=True)]
        return urlunsplit((p.scheme, p.netloc, self.text(p.path), urlencode(query), ""))

    def body(self, value):
        try:
            return json.dumps(self.obj(json.loads(value)), ensure_ascii=False)
        except (ValueError, TypeError):
            return self.text(value)

    def request(self, req):
        record = asdict(req)
        record.update(id=req.id, group=req.group, url=self.url(req.url),
                      headers={k: str(v)[:512] for k, v in list(self.obj(req.headers).items())[:30]}, body=self.body(req.body)[:4000])
        return record


def import_records(path, session="anonymous", owner=""):
    """Yield (request, optional captured response); accept URL TXT, httpx JSONL, HAR."""
    path = Path(path)
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".har" or content.lstrip().startswith('{"log"'):
        har = json.loads(content)
        for entry in har["log"]["entries"]:
            r = entry["request"]
            headers = {h["name"]: h["value"] for h in r.get("headers", [])}
            post = r.get("postData", {})
            body = post.get("text", "")
            # HAR file uploads often omit file bytes; do not invent a replay.
            mime_type = post.get("mimeType", "")
            if mime_type.startswith("application/x-www-form-urlencoded") and not body:
                body = urlencode([(p["name"], p.get("value", "")) for p in post.get("params", []) if "fileName" not in p])
            replayable = ("multipart/" not in mime_type and not any("fileName" in p for p in post.get("params", [])))
            if post.get("mimeType"):
                headers.setdefault("content-type", post["mimeType"])
            req = Request(r["url"], r.get("method", "GET"), headers, body, session, owner, str(path), replayable)
            response = entry.get("response", {})
            response_content = response.get("content", {})
            captured = {"status": response.get("status", 0),
                        "headers": {h["name"].lower(): h["value"] for h in response.get("headers", [])},
                        "body": response_content.get("text", "") if response_content.get("encoding") != "base64" else "[binary omitted]",
                        "captured": True}
            yield req, captured
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            record = json.loads(line)
            req = Request(record.get("url") or record["input"], record.get("method", "GET"), session=session, owner=owner, source=str(path))
            yield req, {"status": record.get("status_code", 0), "headers": {"server": record.get("webserver", "")},
                        "body": record.get("body", ""), "tech": record.get("tech", []), "captured": True}
        else:
            yield Request(line, session=session, owner=owner, source=str(path)), None
