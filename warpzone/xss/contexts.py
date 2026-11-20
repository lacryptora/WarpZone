"""WarpZone XSS arsenal: reflection context detection.

Sends an alphanumeric canary, finds where it lands in the HTML, then sends a
char-probe (<> "' `) to see which metacharacters survive - the two facts that
decide which payload family can work.
"""
import re

_WS = " \t\r\n"


def _last_open(text, i):
    """Char index of the last '<' before position i, plus the tag/comment name."""
    j = text.rfind("<", 0, i)
    if j == -1:
        return None
    return j


def detect(text, canary):
    """Return {'context': name, 'raw_chars': set, 'sample': str} or None."""
    i = text.find(canary)
    if i == -1:
        return None
    before = text[:i]
    tag_open = _last_open(text, i)
    tag_close = text.rfind(">", 0, i)

    # --- inside a <script> block? -----------------------------------------
    s_open = before.rfind("<script")
    s_close = before.rfind("</script")
    if s_open != -1 and s_open > s_close:
        tail = before[s_open:i]
        if re.search(r"""['"`]\s*$""", before[:i]) or re.search(r"""['"`][^'"`]*$""", tail.split("\n")[-1] if tail else ""):
            ctx = "js_string"
        else:
            ctx = "js_code"
        return {"context": ctx, "raw_chars": _raw_chars(text, canary, i),
                "sample": _sample(before, i)}

    # --- inside <style> or <!-- comment ------------------------------------
    st_open, st_close = before.rfind("<style"), before.rfind("</style")
    if st_open != -1 and st_open > st_close:
        return {"context": "css", "raw_chars": _raw_chars(text, canary, i),
                "sample": _sample(before, i)}
    c_open, c_close = before.rfind("<!--"), before.rfind("-->")
    if c_open != -1 and c_open > c_close:
        return {"context": "html_comment", "raw_chars": _raw_chars(text, canary, i),
                "sample": _sample(before, i)}

    # --- inside a tag? ------------------------------------------------------
    if tag_open is not None and (tag_close is None or tag_open > tag_close):
        seg = before[tag_open:i]
        tagname_m = re.match(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)", seg)
        quote = None
        for ch in reversed(seg):
            if ch in "\"'":
                quote = ch
                break
            if ch == ">":
                break
        if tagname_m and tagname_m.group(1).lower() == "script":
            return {"context": "js_code", "raw_chars": _raw_chars(text, canary, i),
                    "sample": _sample(before, i)}
        if quote == '"':
            ctx = "attr_value_dq"
        elif quote == "'":
            ctx = "attr_value_sq"
        elif quote is None and "=" not in seg.rsplit(" ", 1)[-1] and tagname_m:
            ctx = "tag_name"
        else:
            ctx = "attr_value_bare"
        return {"context": ctx, "raw_chars": _raw_chars(text, canary, i),
                "sample": _sample(before, i)}

    return {"context": "html_body", "raw_chars": _raw_chars(text, canary, i),
            "sample": _sample(before, i)}


def _raw_chars(text, canary, i):
    """Which of < > " ' ` appear verbatim around the reflected canary?
    (from a combined probe: canary wrapped in the probe chars)"""
    start = max(0, i - 40)
    window = text[start:i + len(canary) + 40]
    return {c for c in "<>\"'`" if c in window}


def _sample(before, i, width=60):
    return before[max(0, i - width):i].replace("\n", "␤")[-width:]


def char_probe():
    """The metacharacter probe value (alphanumeric core keeps position findable)."""
    return "wz9<>\"'`"
