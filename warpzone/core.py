"""WarpZone core: scope rules, HTTP plumbing, tool bridges, small helpers.

The scope check is the most important thing in here. Every module sends its
targets through it before touching the network, so an out-of-scope host never
gets a request. The scope also understands exclusions: you can say "all of
target.com, but keep away from blog.target.com".
"""
import hashlib
import math
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests

UA = "Mozilla/5.0 (WarpZone; authorized security testing)"
DEFAULT_TIMEOUT = 15

STATIC_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff",
               ".woff2", ".ttf", ".eot", ".ico", ".mp4", ".webm", ".webp",
               ".mp3", ".otf", ".map")

_HOST_RE = re.compile(r"^[a-z0-9._-]+$")


# ---------------------------------------------------------------- scope ----

def is_wildcard(entry):
    """True when a scope line asks for subdomains only (starts with "*.")."""
    return str(entry).strip().lower().startswith("*.")


def parse_scope_entry(entry):
    """Turn one scope line into a bare hostname (drop scheme, wildcard, slash)."""
    e = entry.strip().lower()
    if "://" in e:
        e = urlparse(e).hostname or e
    e = e.lstrip("*").lstrip(".").rstrip("/").rstrip(".")
    return e


class Scope:
    """What you are allowed to touch.

    includes: hosts you may test. They come in two shapes:
      "target.com"    the apex AND every subdomain (covers more)
      "*.target.com"  subdomains only, NOT the apex target.com itself
    excludes: hosts to stay away from, even when an include would cover them.
              An exclude always wins, so "target.com" + exclude "blog.target.com"
              lets you test everything except blog (and blog's subdomains).
    """

    def __init__(self, includes=(), excludes=()):
        self.apex = []   # host -> apex + all subdomains
        self.subs = []   # host -> subdomains only (apex stays out)
        for x in includes:
            host = parse_scope_entry(x)
            if not host:
                continue
            (self.subs if is_wildcard(x) else self.apex).append(host)
        self.excludes = [e for e in (parse_scope_entry(x) for x in excludes) if e]

    @property
    def includes(self):
        """All include hosts (bare), apex ones first. Kept for callers."""
        return list(self.apex) + list(self.subs)

    @staticmethod
    def _clean(host):
        if not host:
            return None
        h = host.lower().rstrip(".")
        return h if _HOST_RE.match(h) else None

    @staticmethod
    def _under(h, entries):
        """True when h is a subdomain of any entry (apex itself not counted)."""
        return any(h.endswith("." + e) for e in entries)

    def allows(self, host):
        h = self._clean(host)
        if not h:
            return False
        if h in self.excludes or self._under(h, self.excludes):
            return False
        if h in self.apex or self._under(h, self.apex):
            return True       # apex rule: the host itself or any subdomain
        return self._under(h, self.subs)   # wildcard rule: subdomains only

    def describe(self):
        """Plain-words summary for the auto-scope note."""
        parts = [e + " and its subdomains" for e in self.apex]
        parts += ["subdomains of " + e + " (not the apex)" for e in self.subs]
        parts += ["never " + e for e in self.excludes]
        return "; ".join(parts) or "none"

    def lines(self):
        """How the scope reads back, for scope_used.txt."""
        return (list(self.apex)
                + ["*." + e for e in self.subs]
                + ["!" + e for e in self.excludes])

    def __iter__(self):
        return iter(self.includes)

    def __bool__(self):
        return bool(self.apex or self.subs)


def in_scope(host, scope):
    """True when host is allowed. Works with a Scope or a plain host list."""
    if isinstance(scope, Scope):
        return scope.allows(host)
    return Scope(scope or []).allows(host)


def scope_from_target(domain=None, url=None, js_list=None):
    """Build a scope straight from the target, so --scope is optional.

    -d telekom.de      -> telekom.de and every subdomain
    -d *.telekom.de    -> subdomains only, NOT telekom.de itself
    -u https://host/x  -> that host and its subdomains
    --js-list file     -> every host seen in the JS URL list

    A bare host covers the apex and its subdomains; a "*." wildcard covers the
    subdomains but leaves the apex out. It never reaches beyond the hosts you
    pointed it at.
    """
    includes = []
    if domain:
        includes.append(domain)   # raw, so "*.target.com" stays subdomains-only
    elif url:
        includes.append(parse_scope_entry(urlparse(url).hostname or ""))
    elif js_list:
        try:
            for line in load_lines(js_list):
                includes.append(parse_scope_entry(urlparse(line).hostname or ""))
        except OSError:
            pass
    includes = list(dict.fromkeys(e for e in includes if e))
    return Scope(includes, [])


def load_scope(path):
    """Read a scope file into a Scope.

    One host per line. A line starting with "!" or "-" is an exclusion.
    Lines starting with "#" are comments.
    """
    includes, excludes = [], []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s[0] in "!-":
            excludes.append(s[1:].strip())
        else:
            includes.append(s)
    return Scope(includes, excludes)


_BAD_URL_CHARS = set(" <>\"'`{}|\\^\n\r\t")


def is_sane_url(u):
    """Reject junk that is not a real URL (spaces, HTML, quotes, huge blobs).

    Keeps WarpZone from fetching and analyzing garbage like
    'https://app.klarna.com/Data plan found from mParticle.js', which the
    endpoint miner sometimes scrapes out of inline HTML or JSON.
    """
    if not u or len(u) > 2000:
        return False
    if any(c in u for c in _BAD_URL_CHARS):
        return False
    p = urlparse(u)
    return p.scheme in ("http", "https") and bool(p.hostname)


def load_lines(path):
    """Read a file into non-empty, non-comment lines."""
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# ------------------------------------------------------------ subprocess ---

def run(cmd, stdin=None, timeout=300, cwd=None):
    """Run a command, give back its stdout lines (empty list if it fails)."""
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return [l for l in p.stdout.splitlines() if l.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


# ------------------------------------------------------------------- http --

def make_session(insecure=False, timeout=DEFAULT_TIMEOUT):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    s.timeout = timeout
    if insecure:
        s.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return s


def get(session, url, **kw):
    """GET with sane defaults; returns None on any network failure."""
    kw.setdefault("timeout", getattr(session, "timeout", DEFAULT_TIMEOUT))
    kw.setdefault("allow_redirects", True)
    try:
        return session.get(url, **kw)
    except requests.RequestException:
        return None


# ------------------------------------------------------------------ utils --

def redact(value, keep=6):
    """Mask the middle of a secret for the report (full value stays in JSON)."""
    v = str(value)
    if len(v) <= keep * 2:
        return v[:2] + "..." + v[-2:]
    return v[:keep] + "..." + v[-4:]


def entropy(s):
    """Shannon entropy (bits per char), used to flag opaque blobs."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def safe_name(url, suffix=""):
    """A filesystem-safe, mostly-unique file name built from a URL."""
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/").replace("/", "_") or "index"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if len(base) > 100:
        base = base[:90] + "_" + hashlib.md5(url.encode()).hexdigest()[:8]
    return base + suffix


def file_sha(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
