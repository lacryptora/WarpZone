"""World 1-2 (COIN HEAVEN, part B): endpoint mining + full normalization pipeline.

Extracts absolute URLs, absolute/relative paths (incl. template literals and
rest-style "api/v1/x" strings), then turns every relative find into a REAL
endpoint by joining it with the JS file's origin - ready to open, probe and
feed to fuzzer/xfx/dalfox.

Pipeline: extract -> normalize -> dedupe -> categorize -> score -> params
          -> (optional) probe liveness with safe GETs.
"""
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

from . import core

# strings in quotes/backticks that look like paths or URLs
ABS_URL_RE = re.compile(
    r"""["'`]((?:https?:)?//[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s"'`<>\\)]*)?)["'`]""", re.I)
REL_PATH_RE = re.compile(
    r"""["'`](/[a-zA-Z0-9_\-./?&=%~:@!$+,;*\[\]{}]{2,200})["'`]""")
SLASHED_RE = re.compile(  # "api/v1/users" — no leading slash
    r"""["'`]([a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-.:?&=%~{}]+)+)["'`]""")
WS_URL_RE = re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]""", re.I)

CATS = [
    ("graphql", ("graphql",)),
    ("auth", ("login", "logout", "signin", "signup", "register", "auth", "token",
              "oauth", "sso", "session", "jwt", "password", "credential")),
    ("admin", ("admin", "administrator", "manage", "console", "dashboard",
               "internal", "private", "root")),
    ("upload", ("upload", "import", "attach")),
    ("debug", ("debug", "trace", "actuator", "swagger", "openapi", "api-docs",
               "healthcheck", "test", "staging", "dev", "sentry", "metrics")),
    ("config", ("config", "env", "settings", "preferences", "properties")),
    ("payment", ("payment", "checkout", "billing", "invoice", "order",
                 "subscription", "stripe", "paypal")),
    ("file", (".pdf", ".json", ".xml", ".csv", ".txt", ".zip", ".bak", ".sql",
              ".xlsx", ".doc", ".log")),
    ("user", ("user", "profile", "account", "customer", "member")),
]
SCORES = {"graphql": 7, "admin": 10, "debug": 8, "config": 7, "auth": 5,
          "upload": 6, "payment": 6, "file": 4, "user": 3, "normal": 1}

INTERESTING_WORDS = ("admin", "debug", "config", "token", "secret", "internal",
                     "upload", "graphql", "actuator", "swagger", "backup",
                     "key", "private", "console", "jwt", "otp", "otp", "email")


def _is_static(path):
    low = path.lower()
    return low.endswith(core.STATIC_EXTS) and not low.endswith(".js")


def extract(text):
    """Raw endpoint candidates from one JS file's text."""
    found = set()
    for rx in (ABS_URL_RE, REL_PATH_RE, WS_URL_RE, SLASHED_RE):
        for m in rx.finditer(text):
            v = m.group(1).strip()
            if not v or _is_static(urlparse(v).path if "://" in v else v):
                continue
            if v.lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
                continue
            if len(v) < 3 or v.count("//") > 2:
                continue
            found.add(v)
    return found


def normalize(ep, js_url):
    """Join a raw find with the JS file's origin -> a real, openable URL."""
    jp = urlparse(js_url)
    origin = f"{jp.scheme}://{jp.netloc}"
    ep = ep.strip().rstrip("\\")
    if ep.lower().startswith(("ws:", "wss:")):
        return ep
    if re.match(r"^https?://", ep, re.I):
        return ep
    if ep.startswith("//"):
        return jp.scheme + ":" + ep
    if ep.startswith("/"):
        return origin + ep
    return origin + "/" + ep


def categorize(url):
    low = url.lower()
    for cat, words in CATS:
        if any(w in low for w in words):
            return cat
    return "normal"


def score(url):
    cat = categorize(url)
    s = SCORES[cat]
    if any(w in url.lower() for w in INTERESTING_WORDS):
        s += 2
    return s


def mine(manifest):
    """Walk every prettified JS file -> endpoints, params, per-file counts."""
    endpoints, per_file = set(), {}
    for entry in manifest:
        text = Path(entry["pretty_file"]).read_text(encoding="utf-8", errors="replace")
        n0 = len(endpoints)
        for raw in extract(text):
            endpoints.add(normalize(raw, entry["url"]))
        per_file[entry["url"]] = len(endpoints) - n0
    params = Counter()
    for ep in endpoints:
        for kv in urlparse(ep).query.split("&"):
            if "=" in kv:
                params[kv.split("=", 1)[0]] += 1
    ranked = sorted(endpoints, key=lambda u: (-score(u), u))
    return ranked, params, per_file


def probe(session, endpoints, scope, threads=10, limit=300, timeout=10):
    """Safe GET probing of in-scope endpoints -> status/title/length."""
    targets = [u for u in endpoints[:limit]
               if core.in_scope(urlparse(u).hostname, scope)]
    out = {}

    def hit(url):
        r = core.get(session, url, timeout=timeout)
        if r is None:
            return url, {"status": None}
        title = re.search(r"<title[^>]*>([^<]{0,120})", r.text or "", re.I)
        return url, {"status": r.status_code, "length": len(r.content or b""),
                     "title": title.group(1).strip() if title else None}

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for url, info in ex.map(hit, targets):
            out[url] = info
    return out


def write(outdir, endpoints, params, live=None):
    """Save endpoints.txt / endpoints_categorized.json / params.txt / live."""
    (outdir / "endpoints.txt").write_text("\n".join(endpoints) + "\n", encoding="utf-8")
    cats = {}
    for ep in endpoints:
        cats.setdefault(categorize(ep), []).append(ep)
    import json
    (outdir / "endpoints_categorized.json").write_text(
        json.dumps({"categories": cats,
                    "scores": {u: score(u) for u in endpoints}}, indent=2),
        encoding="utf-8")
    (outdir / "params.txt").write_text(
        "\n".join(f"{p}\t{c}" for p, c in params.most_common()) + "\n", encoding="utf-8")
    if live is not None:
        rows = [f"{u}\t{v.get('status')}\t{v.get('title') or ''}"
                for u, v in sorted(live.items()) if v.get("status")]
        (outdir / "endpoints_live.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
