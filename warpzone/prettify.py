"""World 1-2 (COIN HEAVEN, part A): fetch JS + prettify.

Order of preference:
  1. jsbeautifier python library
  2. `js-beautify` binary
  3. built-in brace-aware re-indenter (works with zero deps on minified code)

Prettified files are what all later analysis reads, so findings get real line
numbers and humans can actually review them.
"""
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import core

try:
    import jsbeautifier
    HAVE_LIB = True
except ImportError:
    HAVE_LIB = False


# ------------------------------------------------------------- beautify ----

def builtin_beautify(text):
    """Tiny string-aware re-indenter: newline after ; { } but never inside quotes."""
    out, line, depth = [], "", 0
    quote, escaped = None, False

    def emit(dedent=0):
        nonlocal line
        s = line.strip()
        if s:
            out.append("    " * max(depth - dedent, 0) + s)
        line = ""

    for c in text:
        if quote:
            line += c
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == quote:
                quote = None
            continue
        if c in "\"'`":
            quote = c
            line += c
        elif c == "{":
            emit()
            out.append("    " * depth + "{")
            depth += 1
        elif c == "}":
            emit()
            depth = max(depth - 1, 0)
            out.append("    " * depth + "}")
        elif c == ";":
            line += c
            emit()
        elif c == "\n":
            emit()
        else:
            line += c
    emit()
    return "\n".join(out)


def beautify(text):
    if HAVE_LIB:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            opts.preserve_newlines = True
            return jsbeautifier.beautify(text, opts)
        except Exception:
            pass
    if shutil.which("js-beautify"):
        try:
            p = subprocess.run(["js-beautify"], input=text, capture_output=True,
                               text=True, timeout=60)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout
        except Exception:
            pass
    return builtin_beautify(text)


# ------------------------------------------------------------ fetch+save ---

def fetch_one(session, url, outdir, keep_raw=False):
    """Fetch a JS file, save raw + prettified copies. Returns manifest entry."""
    entry = {"url": url, "raw_file": None, "pretty_file": None,
             "pretty_lines": 0, "sha16": None, "engine": None}
    r = core.get(session, url)
    if r is None or not r.text:
        entry["error"] = "fetch failed"
        return entry
    text = r.text
    entry["_raw_text"] = text  # in-memory only: used for sourceMappingURL checks
    entry["sha16"] = core.file_sha(text)
    entry["http_status"] = r.status_code
    if keep_raw:
        base = core.safe_name(url)
        if base.lower().endswith(".js"):
            base = base[:-3]
        raw = outdir / "raw_js" / (base + ".js")
        raw.write_text(text, encoding="utf-8")
        entry["raw_file"] = str(raw)
    pretty = beautify(text)
    entry["engine"] = ("jsbeautifier-lib" if HAVE_LIB
                       else "js-beautify-bin" if shutil.which("js-beautify")
                       else "builtin")
    p = outdir / "prettified" / (base + ".pretty.js")
    p.write_text(pretty, encoding="utf-8")
    entry["pretty_file"] = str(p)
    entry["pretty_lines"] = pretty.count("\n") + 1
    entry["_pretty_text"] = pretty  # in-memory reuse: read the file once, not 3x
    return entry


def fetch_all(session, js_urls, outdir, threads=8, keep_raw=True):
    """Fetch + prettify every JS file concurrently. Returns manifest list."""
    (outdir / "prettified").mkdir(parents=True, exist_ok=True)
    if keep_raw:
        (outdir / "raw_js").mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        entries = list(ex.map(
            lambda u: fetch_one(session, u, outdir, keep_raw), js_urls))
    return [e for e in entries if not e.get("error")]
