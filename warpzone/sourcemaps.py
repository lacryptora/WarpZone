"""World 1-3 (SECRET VAULTS, part B): exposed source maps.

A live  `.js.map`  is near-original source: comments, folder structure, even
whole server-side files if sourcesContent survived the build. We check:
  1. the //# sourceMappingURL= comment inside each JS file
  2. the naive `<file>.js.map` guess (the original js_recon behaviour)
then parse the map, save it, and if sourcesContent exists, reconstruct the
original source tree into outdir/sourcemaps/.
"""
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from . import core

MAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.M)


def scan(session, entry, outdir, download=True, scope=()):
    """Check one JS file for exposed maps. Returns a record or None."""
    url = entry["url"]
    candidates = []
    m = MAP_COMMENT_RE.search(entry.get("_raw_text") or "")
    if m and not m.group(1).startswith("data:"):
        candidates.append(("sourceMappingURL comment", urljoin(url, m.group(1))))
    candidates.append(("naive .map guess", url + ".map"))

    for how, map_url in candidates:
        if not core.in_scope(urlparse(map_url).hostname, scope):
            continue
        r = core.get(session, map_url, timeout=10)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if '"mappings"' not in body[:4000] and '"sources"' not in body[:4000]:
            continue
        rec = {"js_file": url, "map_url": map_url, "found_via": how,
               "level": "PARTIAL", "sources": [], "sources_content": 0}
        try:
            data = json.loads(body)
            rec["sources"] = data.get("sources", [])[:200]
            contents = data.get("sourcesContent") or []
            rec["sources_content"] = sum(1 for c in contents if c)
            rec["sourceRoot"] = data.get("sourceRoot", "")
            rec["file"] = data.get("file", "")
        except ValueError:
            data = None
        if rec["sources_content"]:
            rec["level"] = "FULL_ORIGINAL_SOURCE"
        if download:
            _save(session, map_url, data, body, outdir, rec)
        return rec
    return None


def _save(session, map_url, data, body, outdir, rec):
    base = core.safe_name(map_url)
    if base.lower().endswith(".map"):
        base = base[:-4]
    d = outdir / "sourcemaps"
    d.mkdir(parents=True, exist_ok=True)
    (d / (base + ".map.json")).write_text(body, encoding="utf-8")
    rec["saved"] = str(d / (base + ".map.json"))
    if data and rec["sources_content"]:
        # reconstruct the original source tree
        root = data.get("sourceRoot") or ""
        for src, content in zip(data.get("sources", []), data.get("sourcesContent") or []):
            if not content:
                continue
            rel = (root + src) if root and not src.startswith(root) else src
            rel = re.sub(r"^[a-zA-Z]+://[^/]*", "", rel).lstrip("/")
            rel = rel.replace("..", "__").replace("\\", "_")
            if not rel:
                rel = "unknown.js"
            f = d / (base + "_src") / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content, encoding="utf-8")
        rec["restored_dir"] = str(d / (base + "_src"))


def scan_all(session, manifest, outdir, hud, download=True, scope=()):
    found = []
    for entry in manifest:
        rec = scan(session, entry, outdir, download, scope)
        if rec:
            found.append(rec)
            hud.sourcemap_found()
            hud.item(f"SOURCE MAP EXPOSED [{rec['level']}]: {rec['map_url']}")
    return found
