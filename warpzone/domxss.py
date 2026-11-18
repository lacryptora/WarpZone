"""World 1-4 (BOWSER'S CASTLE, part A): DOM-XSS source->sink taint leads.

Regex dataflow heuristics over prettified JS:
  - every SINK occurrence (innerHTML, eval, document.write, location=...) gets a line number
  - we look for attacker-controlled SOURCES (location.hash, postMessage, ...)
    on the same line (HIGH), within 6 lines above (MEDIUM) or anywhere in the
    file (LOW)
  - file-level sanitizer detection (DOMPurify/escapeHTML/...) downgrades confidence

These are LEADS for manual testing - each lead ships with a test recipe.
"""
import re

# (regex, category, recipe)
SINKS = [
    (re.compile(r"\.innerHTML\s*="), "html-sink",
     "Inject <img src=x onerror=alert(1)> via the source that feeds it"),
    (re.compile(r"\.outerHTML\s*="), "html-sink", "Same as innerHTML — payload replaces the whole node"),
    (re.compile(r"insertAdjacentHTML\s*\("), "html-sink", "Payload in the html argument; try beforeend/afterbegin positions"),
    (re.compile(r"document\.write(?:ln)?\s*\("), "html-sink", "Payload overwrites the page — <svg onload=alert(1)>"),
    (re.compile(r"(?<![\w$.])eval\s*\("), "js-sink", "Direct code execution: alert(1) as the argument"),
    (re.compile(r"(?<![\w$.])(?:setTimeout|setInterval)\s*\(\s*['\"`]"), "js-sink",
     "String arg is eval-like: setTimeout('alert(1)')"),
    (re.compile(r"new\s+Function\s*\("), "js-sink", "Function('...alert(1)...') executes the body"),
    (re.compile(r"(?<![\w$.])execScript\s*\("), "js-sink", "IE-style eval — alert(1) directly"),
    (re.compile(r"globalEval\s*\("), "js-sink", "jQuery globalEval = indirect eval"),
    (re.compile(r"\.html\s*\("), "html-sink", "jQuery .html() = raw HTML injection"),
    (re.compile(r"dangerouslySetInnerHTML"), "html-sink", "React raw-HTML escape hatch — prop value is your payload"),
    (re.compile(r"\bsrcdoc\b"), "html-sink", "iframe srcdoc is its own document — full HTML payload"),
    (re.compile(r"setAttribute\s*\(\s*['\"](?:src|href|action|formaction|onclick|on[a-z]+)"), "attr-sink",
     "setAttribute('onclick', user) — payload must be pure JS: alert(1)"),
    (re.compile(r"(?:window\.|document\.)?location\.(?:href|replace|assign)\s*[+\-]?="), "url-sink",
     "javascript:alert(1) or open-redirect via //evil.com"),
    (re.compile(r"(?:window\.|document\.)?location\s*=\s*[^=]"), "url-sink", "javascript: / protocol-relative redirect"),
    (re.compile(r"window\.open\s*\("), "url-sink", "javascript: URL or open redirect"),
    (re.compile(r"jQuery\([^)]*\)\.load\s*\(|\$\.load\s*\("), "url-sink", "jQuery .load() injects fetched HTML"),
    (re.compile(r"addEventListener\s*\(\s*['\"]message['\"]"), "handler",
     "postMessage listener — send crafted event with a bad origin from console"),
    (re.compile(r"\.onmessage\s*="), "handler", "postMessage handler — same origin-check test"),
]

SOURCES = [
    (re.compile(r"location\.hash"), "location.hash", "#<img src=x onerror=alert(1)>"),
    (re.compile(r"location\.search"), "location.search", "?q=<svg onload=alert(1)>"),
    (re.compile(r"\blocation\.href\b"), "location.href", "page#payload / ?q=payload"),
    (re.compile(r"document\.(?:URL|documentURI|baseURI)"), "document.URL", "fragment payload"),
    (re.compile(r"document\.referrer"), "document.referrer", "poisoned Referer header"),
    (re.compile(r"document\.cookie"), "document.cookie", "cookie value → sink (needs a cookie-setting vector)"),
    (re.compile(r"window\.name"), "window.name", "set window.name in console, then reload"),
    (re.compile(r"event\.data|\.data\s*[,)]"), "postMessage event.data", "postMessage(obj,'*') from console"),
    (re.compile(r"localStorage\.getItem|localStorage\["), "localStorage", "set localStorage key in console"),
    (re.compile(r"sessionStorage\.getItem|sessionStorage\["), "sessionStorage", "set sessionStorage key in console"),
    (re.compile(r"URLSearchParams"), "URLSearchParams", "?param=<svg onload=alert(1)>"),
    (re.compile(r"history\.state"), "history.state", "pushState with payload"),
]

SANITIZERS = ("DOMPurify", "sanitize", "sanitizer", "escapeHTML", "encodeHTML",
              "filterXSS", "textContent", "escape(")


def _snip(line, width=180):
    s = line.strip()
    return s if len(s) <= width else s[:width] + "…"


def analyze(manifest, window=6):
    """Return DOM-XSS leads across every prettified JS file."""
    leads = []
    for entry in manifest:
        path = entry["pretty_file"]
        text = open(path, encoding="utf-8", errors="replace").read()
        lines = text.splitlines()
        sanitized = any(s in text for s in SANITIZERS)
        file_sources = [name for rx, name, _ in SOURCES if rx.search(text)]
        file_sinks = [(rx, cat, recipe) for rx, cat, recipe in SINKS if rx.search(text)]
        if not file_sinks:
            continue

        for lineno, line in enumerate(lines, 1):
            for rx, cat, recipe in file_sinks:
                if not rx.search(line):
                    continue
                same = [name for srx, name, _ in SOURCES if srx.search(line)]
                if same:
                    lvl, srcs = "high", same
                else:
                    nearby = [name for srx, name, _ in SOURCES
                              if any(srx.search(l) for l in lines[max(0, lineno - 1 - window):lineno - 1])]
                    lvl, srcs = ("medium", nearby) if nearby else ("low", file_sources)
                if lvl == "low" and not file_sources:
                    continue  # sink with no source anywhere: not a DOM-XSS lead
                lead = {
                    "file": entry["url"], "pretty_file": path, "line": lineno,
                    "sink": rx.pattern, "category": cat, "sources": srcs,
                    "taint": lvl, "snippet": _snip(line), "recipe": recipe,
                    "sanitizer_in_file": sanitized,
                    "payload_seed": _seed_payload(cat),
                }
                if sanitized:
                    lead["taint"] = "low"
                    lead["note"] = "sanitizer present in file — verify it really covers this flow"
                leads.append(lead)
    return leads


def _seed_payload(category):
    return {
        "html-sink": "<img src=x onerror=alert(1)>",
        "js-sink": "alert(1)",
        "url-sink": "javascript:alert(1)  |  #\"><img src=x onerror=alert(1)>",
        "attr-sink": "alert(1)  (pure JS — it lands inside a handler)",
        "handler": "postMessage({'x':'<img src=x onerror=alert(1)>'},'*') from console",
    }.get(category, "<svg onload=alert(1)>")


def write(outdir, leads):
    import json
    (outdir / "dom_xss_leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
