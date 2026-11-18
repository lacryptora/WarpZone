"""WarpZone core: scope enforcement, HTTP plumbing, subprocess bridges, utils.

The scope check (`in_scope`) is the single most important function in the
project — every module funnels its targets through it before any request.
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


# ---------------------------------------------------------------- scope ----

def parse_scope_entry(entry):
    """Normalize one scope entry to a bare hostname suffix (no scheme/wildcard)."""
    e = entry.strip().lower()
    if "://" in e:
        e = urlparse(e).hostname or e
    e = e.lstrip("*").lstrip(".").rstrip("/").rstrip(".")
    return e


def in_scope(host, scope_entries):
    """True if host is inside scope.

    A bare entry 'target.com' covers target.com and every subdomain;
    '*.target.com' behaves the same (we treat leading wildcards as the
    suffix form). Off-scope hosts are ALWAYS refused.
    """
    if not host:
        return False
    h = host.lower().rstrip(".")
    if not re.match(r"^[a-z0-9._-]+$", h):
        return False
    for entry in scope_entries:
        e = parse_scope_entry(entry)
        if e and (h == e or h.endswith("." + e)):
            return True
    return False


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
    """Run a command, return stdout lines (empty list on any failure)."""
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
    """Mask the middle of a secret for report display (full value stays in JSON)."""
    v = str(value)
    if len(v) <= keep * 2:
        return v[:2] + "…" + v[-2:]
    return v[:keep] + "…" + v[-4:]


def entropy(s):
    """Shannon entropy (bits/char) — used to flag opaque high-entropy blobs."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def safe_name(url, suffix=""):
    """Filesystem-safe, unique-ish file name derived from a URL."""
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/").replace("/", "_") or "index"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if len(base) > 100:
        base = base[:90] + "_" + hashlib.md5(url.encode()).hexdigest()[:8]
    return base + suffix


def file_sha(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
