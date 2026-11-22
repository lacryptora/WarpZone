"""World 1-4 (BOWSER'S CASTLE, part A): DOM-XSS source-to-sink taint leads.

Regex dataflow heuristics over prettified JS:
  - every SINK hit (innerHTML, eval, document.write, location=...) gets a line number
  - we look for attacker-controlled SOURCES (location.hash, postMessage, ...)
    on the same line (HIGH), within 6 lines above (MEDIUM) or anywhere in the
    file (LOW)
  - a sanitizer in the file (DOMPurify/escapeHTML/...) lowers confidence

These are LEADS for hands-on testing, and each one ships with a test recipe.
Point the --confirm browser checker at the pages that load this JS to turn a
likely lead into a real, fired XSS.
"""
import re

# (regex, category, recipe)
SINKS = [
    (re.compile(r"\.innerHTML\s*="), "html-sink",
     "Inject <img src=x onerror=alert(1)> via the source that feeds it"),
    (re.compile(r"\.outerHTML\s*="), "html-sink", "Same as innerHTML - payload replaces the whole node"),
    (re.compile(r"insertAdjacentHTML\s*\("), "html-sink", "Payload in the html argument; try beforeend/afterbegin positions"),
    (re.compile(r"document\.write(?:ln)?\s*\("), "html-sink", "Payload overwrites the page - <svg onload=alert(1)>"),
    (re.compile(r"(?<![\w$.])eval\s*\("), "js-sink", "Direct code execution: alert(1) as the argument"),
    (re.compile(r"(?<![\w$.])(?:setTimeout|setInterval)\s*\(\s*['\"`]"), "js-sink",
     "String arg is eval-like: setTimeout('alert(1)')"),
    (re.compile(r"new\s+Function\s*\("), "js-sink", "Function('...alert(1)...') executes the body"),
    (re.compile(r"(?<![\w$.])execScript\s*\("), "js-sink", "IE-style eval - alert(1) directly"),
    (re.compile(r"globalEval\s*\("), "js-sink", "jQuery globalEval = indirect eval"),
    (re.compile(r"\.html\s*\("), "html-sink", "jQuery .html() = raw HTML injection"),
    (re.compile(r"dangerouslySetInnerHTML"), "html-sink", "React raw-HTML escape hatch - prop value is your payload"),
    (re.compile(r"\bsrcdoc\b"), "html-sink", "iframe srcdoc is its own document - full HTML payload"),
    (re.compile(r"setAttribute\s*\(\s*['\"](?:src|href|action|formaction|onclick|on[a-z]+)"), "attr-sink",
     "setAttribute('onclick', user) - payload must be pure JS: alert(1)"),
    (re.compile(r"(?:window\.|document\.)?location\.(?:href|replace|assign)\s*[+\-]?="), "url-sink",
     "javascript:alert(1) or open-redirect via //evil.com"),
    (re.compile(r"(?:window\.|document\.)?location\s*=\s*[^=]"), "url-sink", "javascript: / protocol-relative redirect"),
    (re.compile(r"window\.open\s*\("), "url-sink", "javascript: URL or open redirect"),
    (re.compile(r"jQuery\([^)]*\)\.load\s*\(|\$\.load\s*\("), "url-sink", "jQuery .load() injects fetched HTML"),
    (re.compile(r"addEventListener\s*\(\s*['\"]message['\"]"), "handler",
     "postMessage listener - send crafted event with a bad origin from console"),
    (re.compile(r"\.onmessage\s*="), "handler", "postMessage handler - same origin-check test"),
]

SOURCES = [
    (re.compile(r"location\.hash"), "location.hash", "#<img src=x onerror=alert(1)>"),
    (re.compile(r"location\.search"), "location.search", "?q=<svg onload=alert(1)>"),
    (re.compile(r"\blocation\.href\b"), "location.href", "page#payload / ?q=payload"),
    (re.compile(r"document\.(?:URL|documentURI|baseURI)"), "document.URL", "fragment payload"),
    (re.compile(r"document\.referrer"), "document.referrer", "poisoned Referer header"),
    (re.compile(r"document\.cookie"), "document.cookie", "cookie value -> sink (needs a cookie-setting vector)"),
    (re.compile(r"window\.name"), "window.name", "set window.name in console, then reload"),
    (re.compile(r"\b(?:event|evt|ev|msg|message)\.data\b"), "postMessage event.data",
     "postMessage(obj,'*') from console"),
    (re.compile(r"localStorage\.getItem|localStorage\["), "localStorage", "set localStorage key in console"),
    (re.compile(r"sessionStorage\.getItem|sessionStorage\["), "sessionStorage", "set sessionStorage key in console"),
    (re.compile(r"URLSearchParams"), "URLSearchParams", "?param=<svg onload=alert(1)>"),
    (re.compile(r"history\.state"), "history.state", "pushState with payload"),
]

SANITIZERS = ("DOMPurify", "sanitize", "sanitizer", "escapeHTML", "encodeHTML",
              "filterXSS", "textContent", "escape(")

# postMessage is only a real source when the file actually listens for messages.
MSG_LISTENER = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=")

# Shared libraries and framework runtimes. Sinks in here are the library's own
# internals, not your app's data flow, so they are almost always false positives.
VENDOR_HINTS = ("jquery", "react-dom", "react.production", "react.development",
                "mediaelement", "lodash", "moment.min", "polyfill", "bootstrap",
                "angular", "zone.js", "core-js", "evergreen.core", "/webpack",
                "/runtime")
VENDOR_RE = re.compile(r"_next/static/chunks/(?:framework|main|webpack|polyfills|runtime)-")

# Ranking: eval-family worst, then raw HTML, then url/attr, then bare handlers.
_CAT_WEIGHT = {"js-sink": 5, "html-sink": 4, "url-sink": 3, "attr-sink": 2, "handler": 1}
_TAINT_WEIGHT = {"high": 100, "medium": 40}


def _is_vendor(url):
    u = (url or "").lower()
    return bool(VENDOR_RE.search(u)) or any(h in u for h in VENDOR_HINTS)


def _score(lead):
    s = _TAINT_WEIGHT.get(lead["taint"], 0)
    s += _CAT_WEIGHT.get(lead["category"], 0)
    if not lead.get("sanitizer_in_file"):
        s += 25     # a flow with no sanitizer anywhere is worth a closer look
    return s


def _snip(line, width=180):
    s = line.strip()
    return s if len(s) <= width else s[:width] + "..."


def analyze(manifest, window=6):
    """Return DOM-XSS leads, ranked, with the noise cut out.

    A lead only survives when an attacker source sits ON the sink line (high)
    or within `window` lines either side of it (medium). A source that merely
    appears somewhere else in the file is NOT counted - that was the old flood
    of bogus 'postMessage' tags. Library/framework files are skipped entirely,
    and postMessage only counts when the file really listens for messages.
    """
    leads = []
    for entry in manifest:
        url = entry.get("url", "")
        path = entry.get("pretty_file", "")
        if _is_vendor(url) or _is_vendor(path):
            continue   # library internals, not your data flow

        text = entry.get("_pretty_text")
        if text is None:
            text = open(path, encoding="utf-8", errors="replace").read()
        lines = text.splitlines()
        sanitized = any(s in text for s in SANITIZERS)
        has_msg = bool(MSG_LISTENER.search(text))
        # Drop postMessage as a candidate source when nothing listens for it.
        sources = [(rx, name, hint) for rx, name, hint in SOURCES
                   if has_msg or name != "postMessage event.data"]
        file_sinks = [(rx, cat, recipe) for rx, cat, recipe in SINKS if rx.search(text)]
        if not file_sinks:
            continue

        for lineno, line in enumerate(lines, 1):
            for rx, cat, recipe in file_sinks:
                if not rx.search(line):
                    continue
                same = [name for srx, name, _ in sources if srx.search(line)]
                if same:
                    lvl, srcs = "high", same
                else:
                    lo, hi = max(0, lineno - 1 - window), min(len(lines), lineno + window)
                    ctx = lines[lo:lineno - 1] + lines[lineno:hi]
                    nearby = [name for srx, name, _ in sources
                              if any(srx.search(l) for l in ctx)]
                    if not nearby:
                        continue   # no source near the sink: not a real lead
                    lvl, srcs = "medium", nearby
                lead = {
                    "file": url, "pretty_file": path, "line": lineno,
                    "sink": rx.pattern, "category": cat, "sources": srcs,
                    "taint": lvl, "snippet": _snip(line), "recipe": recipe,
                    "sanitizer_in_file": sanitized,
                    "payload_seed": _seed_payload(cat),
                }
                if sanitized:
                    lead["note"] = "sanitizer present in file - verify it really covers this flow"
                lead["score"] = _score(lead)
                leads.append(lead)

    leads.sort(key=lambda L: L["score"], reverse=True)
    return leads


def _seed_payload(category):
    return {
        "html-sink": "<img src=x onerror=alert(1)>",
        "js-sink": "alert(1)",
        "url-sink": "javascript:alert(1)  |  #\"><img src=x onerror=alert(1)>",
        "attr-sink": "alert(1)  (pure JS - it lands inside a handler)",
        "handler": "postMessage({'x':'<img src=x onerror=alert(1)>'},'*') from console",
    }.get(category, "<svg onload=alert(1)>")


def write(outdir, leads):
    import json
    (outdir / "dom_xss_leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
