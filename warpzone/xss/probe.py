"""World 1-4 (BOWSER'S CASTLE, part B): reflection probing + dalfox bridge.

Active-but-benign XSS lead generation, strictly behind the --xss flag and the
scope check:

  phase 1  inject an alphanumeric canary into every candidate param -> who reflects?
  phase 2  reflect a metachar probe (<> "' `)                       -> what survives?
  phase 3  fire context-fitted payloads (benign alert markers)      -> full reflection?
  phase 4  optional dalfox bridge for browser-verified confirmation

Verdicts are LEADS: reflection != execution. Always confirm in a browser.
"""
import hashlib
import shutil
from urllib.parse import parse_qsl, urlencode, urlparse

from . import contexts, payloads as pl
from .. import core

DEFAULT_PARAMS = [
    "q", "search", "query", "s", "id", "name", "msg", "message", "text",
    "input", "data", "value", "keyword", "email", "user", "username", "page",
    "filter", "sort", "redirect", "url", "next", "return", "callback",
    "comment", "content", "description", "title", "view", "path", "file",
]


def set_param(url, param, value):
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
         if k != param]
    q.append((param, value))
    return p._replace(query=urlencode(q)).geturl()


def _canary(base, param):
    return "wz" + hashlib.md5((base + param).encode()).hexdigest()[:8]


def probe_param(session, url, param, max_payloads=6, timeout=10):
    """Full 3-phase probe of one (url, param). Returns a result dict or None."""
    base = url.split("?")[0]
    canary = _canary(base, param)

    r = core.get(session, set_param(base, param, canary), timeout=timeout)
    if r is None or canary not in (r.text or ""):
        return None

    # phase 2: metachar survival
    probe_chars = "".join(c for c in "<>\"'`" if c not in canary)
    r2 = core.get(session, set_param(base, param, canary + probe_chars), timeout=timeout)
    ctx = contexts.detect(r2.text if r2 and r2.text else r.text, canary)
    raw = ctx.get("raw_chars", set()) if ctx else set()

    res = {
        "url": url, "param": param, "canary": canary,
        "context": ctx["context"] if ctx else "unknown",
        "raw_chars": sorted(raw),
        "sample_before": ctx.get("sample", "") if ctx else "",
        "verdict": "REFLECTED", "payload": None, "family": None,
        "dalfox": [],
    }
    if ctx is None:
        res["verdict"] = "REFLECTED_UNLOCATED"
        return res

    # phase 3: context-fitted payloads
    best = None
    for pay in pl.for_context(ctx["context"], max_payloads):
        marked = pl.canaryfy(pay, canary + "p")
        rp = core.get(session, set_param(base, param, marked), timeout=timeout)
        if rp is not None and (canary + "p") in (rp.text or ""):
            best = pay
            break
    if best:
        res["verdict"] = "REFLECTED_UNFILTERED"
        res["payload"] = pl.canaryfy(best, canary + "p")
        res["family"] = "full payload reflected - browser-verify for execution"
    elif raw:
        res["verdict"] = "REFLECTED_FILTERED"
        res["payload"] = "context=%s, surviving chars: %s" % (
            ctx["context"], " ".join(sorted(raw)) or "none")
        res["family"] = "filter present - try polyglots/filter_probe, check other params"
    return res


def run(session, targets, scope, params_extra=(), threads=5, max_params=8,
        max_payloads=6, timeout=10):
    """Probe every in-scope target URL. Returns result list."""
    from concurrent.futures import ThreadPoolExecutor

    work = []
    for url in targets:
        if not core.in_scope(urlparse(url).hostname, scope):
            continue
        base_params = [k for k, _ in parse_qsl(urlparse(url).query)]
        plist = list(dict.fromkeys(base_params + list(params_extra) + DEFAULT_PARAMS))[:max_params]
        for param in plist:
            work.append((url, param))

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(lambda w: probe_param(session, w[0], w[1],
                                                max_payloads, timeout), work):
            if res:
                results.append(res)
    return results


def dalfox_bridge(targets, scope, limit=25, timeout=180):
    """Run dalfox over the juiciest param'd URLs if it is installed."""
    if not shutil.which("dalfox"):
        return []
    out = []
    paramd = [u for u in targets
              if urlparse(u).query and core.in_scope(urlparse(u).hostname, scope)]
    for url in paramd[:limit]:
        for line in core.run(["dalfox", "url", url, "--no-color", "--silence"],
                             timeout=timeout):
            if line.startswith("[V]") or "[POC]" in line or line.startswith("[G]"):
                out.append({"url": url, "dalfox_line": line})
    return out
