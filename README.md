#  WARPZONE

```
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗███████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗╚══███╔╝██╔═══██╗████╗  ██║██╔════╝
██║ █╗ ██║███████║██████╔╝██████╔╝  ███╔╝ ██║   ██║██╔██╗ ██║█████╗
██║███╗██║██╔══██║██╔═══╝ ██╔═══╝  ███╔╝  ██║   ██║██║╚██╗██║██╔══╝
╚███╔███╔╝██║  ██║██║     ██║     ███████╗╚██████╔╝██║ ╚████║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

**A JavaScript recon & XSS arsenal for bug hunters.**
Every JS file is a warp pipe: jump in and come out with hidden endpoints,
secrets, exposed source maps and DOM-XSS leads.

---

##  What it does (the 5 worlds)

| World | Name | What happens |
| --- | --- | --- |
| **1-1** |  WARP PIPES | Collects in-scope JS via **gau / waymore / katana / hakrawler** bridges + a built-in spider; liveness-checked with **httpx** or threaded GETs |
| **1-2** |  COIN HEAVEN | Downloads every JS file, **prettifies** it (js-beautifier → binary → built-in fallback), then mines **endpoints**: absolute URLs, API paths, template literals, axios/fetch strings - normalizes every find into a **real, openable URL**, categorizes + scores it, extracts param names |
| **1-3** |  SECRET VAULTS | 35+ pattern **secrets DB** (AWS, Google, GitHub, Slack, Stripe, Firebase, Telegram, private keys, JWTs…), generic literal scanner, **high-entropy blob finder**; finds **exposed `.map` source maps** (both `sourceMappingURL` comments and naive `.map` guesses) and **reconstructs the original source tree** |
| **1-4** |  BOWSER'S CASTLE | **DOM-XSS taint engine**: sources (location.hash, postMessage, localStorage…) → sinks (innerHTML, eval, document.write, location=…) with line numbers, taint level (high/medium/low), sanitizer detection and a test recipe per lead. Then the **XSS arena**: reflection probing (canary → metachar probe → context-fitted payloads) with a **dalfox bridge** |
| **1-5** |  REPORT CASTLE | Writes `report_warpzone.md` + `report_warpzone.html` + machine-readable `findings.json`, plus per-artifact files |

##  Install

```bash
# core + game HUD + beautifier
pip install -e ".[all]"

# or the one-shot script (also lists optional community bridges)
bash setup.sh

# or docker
docker build -t warpzone . && docker run --rm warpzone --demo
```

**Requirements:** Python 3.9+, `requests`. `rich` (game HUD) and
`jsbeautifier` (prettifier) are optional - WarpZone has plain-output and
built-in-beautifier fallbacks, so it runs anywhere.

##  Quickstart

```bash
# self-contained showcase: boots a fake vulnerable app on 127.0.0.1
# and runs the FULL pipeline against it (no scope file needed)
warpzone --demo
```

Real run:

```bash
warpzone -d target.com --scope scope.txt                       # passive recon
warpzone -d target.com --scope scope.txt --probe               # + endpoint probing
warpzone -d target.com --scope scope.txt --probe --xss         # + XSS reflection arena
warpzone -u https://target.com/app --scope scope.txt --xss --dalfox
warpzone --js-list jsurls.txt --scope scope.txt --no-bridges
```

What a run looks like:

```
=== WORLD 1-1: WARP PIPES — collecting JS files from every green pipe ===
· 4 in-scope .js URLs — confirming liveness
(♪ 1-UP!) 4 live JS files collected + 3 pages

=== WORLD 1-2: COIN HEAVEN — prettifying + mining endpoints (coins!) ===
  -> http://target.com/admin/panel
  -> http://target.com/actuator/health
  -> http://target.com/graphql
*** COURSE CLEAR — WORLD 1-2 COIN HEAVEN | SCORE 0004000  COINS 00019 ***

=== WORLD 1-3: SECRET VAULTS — secrets & exposed source maps ===
  -> [SECRET high] AWS Access Key — https://target.com/vault.js
♪ 1-UP! EXPOSED SOURCE MAP — 2500 PTS (near-original source!)
  -> SOURCE MAP EXPOSED [FULL_ORIGINAL_SOURCE]: https://target.com/chunk.js.map

=== WORLD 1-4: BOWSER'S CASTLE — DOM-XSS taint leads + XSS arena ===
  -> [high] html-sink — app.pretty.js:22
  -> [REFLECTED_UNFILTERED] https://target.com/search?q=hello+world param=q ctx=html_body

=== WORLD 1-5: REPORT CASTLE — writing the war-room report ===
[+] COURSE CLEAR — score 0006800 (11 endpoints, 10 secrets, 1 maps, 10 DOM leads, 1 reflections)
```

##  CLI reference

| Flag | Effect |
| --- | --- |
| `-d DOMAIN` / `-u URL` / `--js-list FILE` / `--demo` | pick the target (mutually exclusive) |
| `--scope FILE` | **required** scope file, one host per line (see `scope.example.txt`) |
| `--bridges gau,waymore,katana,hakrawler` | choose crawl bridges (installed ones auto-run by default) |
| `--no-bridges` | built-in spider only |
| `--depth`, `--max-pages` | crawler depth / spider page cap |
| `--probe` | safe-GET probe of discovered endpoints (status + title) |
| `--xss` | **active** XSS reflection arena (GET-only, benign markers) |
| `--xss-url URL`, `--xss-params p1,p2` | target the arena precisely |
| `--xss-max-params`, `--xss-max-payloads`, `--xss-endpoints-limit` | arena budgets |
| `--dalfox` | bridge to dalfox for browser-verified confirmation |
| `--download-js` / `--no-raw` | raw JS copies are saved by default |
| `--entropy N` | threshold for the high-entropy blob finder (default 4.2) |
| `--threads`, `--timeout`, `--insecure` | transport knobs |
| `--no-game` | plain output, no Mario HUD |
| `--out DIR` | output directory (default `warpzone_<target>_<ts>`) |

##  Community tool bridges

WarpZone is stronger with friends installed (all optional):

| Tool | Role | Install |
| --- | --- | --- |
| [gau](https://github.com/lc/gau) | archived URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [waymore](https://github.com/xnl-h4ck3r/waymore) | deeper archived URLs | `pip install waymore` |
| [katana](https://github.com/projectdiscovery/katana) | JS-aware crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [hakrawler](https://github.com/hakluke/hakrawler) | fast crawler | `go install github.com/hakluke/hakrawler@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | liveness | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [jsluice](https://github.com/BishopFox/jsluice) | deeper URL extraction (planned hook) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| [dalfox](https://github.com/hahwul/dalfox) | XSS confirmation | `go install github.com/hahwul/dalfox/v2@latest` |

No bridges installed? Everything still works - the built-in spider, threaded
liveness checks and the regex extraction engine are always available.

##  The XSS arsenal

1. **DOM-XSS taint engine** : regex dataflow over prettified JS: every sink
   gets a line number and a taint level (same-line source = `high`, nearby =
   `medium`, file-level = `low`). Sanitizer presence (DOMPurify, escapeHTML,
   `textContent`…) downgrades confidence with a note. Every lead ships a
   **recipe**: what to inject and how to reach it.
2. **Payload database** : 15 families: basic, event handlers, tag/script/attr
   breakers, JS string/code contexts, `javascript:` URLs, HTML comment/CSS
   contexts, DOM-hash payloads, polyglots, filter probes (case tricks,
   encodings, nesting), and blind/OOB templates you point at **your own**
   callback host (`YOUR-OAST-HOST`).
3. **Context detection**: the probe finds *where* your canary landed
   (HTML body, attribute double/single-quoted, tag name, `<script>` string
   vs code, comment, CSS) and *which metacharacters survive* - then fires
   only context-fitted payloads.
4. **Reflection verdicts** : `REFLECTED_UNFILTERED` (whole payload echoed -
   browser-verify now), `REFLECTED_FILTERED` (chars stripped - try polyglots),
   `REFLECTED` (echo only). Reflection ≠ execution: **always confirm in a
   browser** before reporting.
5. **dalfox bridge** : hands the juicy param'd URLs to dalfox when installed.

All payloads are benign `alert()` markers for authorized testing only.

## Output files

| File | What it is |
| --- | --- |
| `report_warpzone.md` / `report_warpzone.html` | the war-room report (HTML is self-contained + responsive) |
| `findings.json` | everything, machine-readable (unredacted secrets for validation) |
| `endpoints.txt` / `endpoints_live.txt` / `endpoints_categorized.json` | endpoints, ranked by interest score; probe results |
| `params.txt` | param names worth reflection testing |
| `secrets.json` | secret leads with validation hints |
| `dom_xss_leads.json` | taint leads with line numbers + recipes |
| `prettified/` | beautified JS - **read these** |
| `raw_js/` | the original files as served |
| `sourcemaps/` | exposed `.map` files + restored original source tree |


## Credits

Created by **Shaimaa Khattab**.

Built on the shoulders of giants: gau, waymore, katana, hakrawler, httpx,
jsluice, dalfox, js-beautifier, rich.

## License

MIT [LICENSE](LICENSE). 
