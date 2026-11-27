# WARPZONE

```
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗███████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗╚══███╔╝██╔═══██╗████╗  ██║██╔════╝
██║ █╗ ██║███████║██████╔╝██████╔╝  ███╔╝ ██║   ██║██╔██╗ ██║█████╗
██║███╗██║██╔══██║██╔══██╗██╔═══╝  ███╔╝  ██║   ██║██║╚██╗██║██╔══╝
╚███╔███╔╝██║  ██║██║  ██║██║     ███████╗╚██████╔╝██║ ╚████║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

A JavaScript recon and XSS toolkit for bug hunters. Every JS file is a warp
pipe: jump in and come out with hidden endpoints, secrets, exposed source maps,
DOM-XSS leads.



## What it does

Five quick stages:

1. WARP PIPES: find in-scope JS with gau / waymore / katana / hakrawler, plus a
   built-in spider. No tools installed? The spider still works.
2. COIN HEAVEN: download and prettify the JS, then pull out endpoints, API
   paths, and parameter names.
3. SECRET VAULTS: scan JS for API keys, tokens, private keys, high-entropy
   blobs, and exposed `.map` source maps (it rebuilds the original source tree).
4. BOWSER'S CASTLE: find DOM-XSS leads (source to sink, with line numbers),
   reflection-probe parameters, and confirm real DOM XSS in a headless browser.
5. REPORT CASTLE: write a Markdown, HTML, and JSON report.

## Install

```bash
# everything: core, HUD, JS beautifier, browser confirm
pip install -e ".[all]"

# the headless browser used by --confirm
playwright install chromium
```

Only `requests` is required. `rich` (the HUD), `jsbeautifier` (prettifier), and
`playwright` (browser confirm) are optional. WarpZone has fallbacks, so it runs
without them, but `--confirm` needs Playwright.

### Ubuntu / WSL from scratch

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv python3-dev build-essential golang-go

git clone https://github.com/lacryptora/WarpZone.git
cd WarpZone
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[all]"
playwright install chromium
```

Optional crawlers and the dalfox bridge (install the ones you want):

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc && source ~/.bashrc
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hahwul/dalfox/v2@latest
pip install waymore
```

## Targets

Give WarpZone a target any way you like:

```bash
warpzone -d target.com                 # the apex AND all subdomains
warpzone -d "*.target.com"             # subdomains only, NOT target.com itself
warpzone -u https://target.com/app     # a URL (that host and its subdomains)
warpzone --targets targets.txt         # a file mixing domains, wildcards, and URLs
warpzone --js-list jsurls.txt          # a file of JS URLs to read directly
```

`target.com` and `*.target.com` are not the same:

- `target.com` covers `target.com` plus every subdomain (`www.`, `api.`, ...).
- `*.target.com` covers the subdomains but leaves the apex `target.com` out.

Use the wildcard form when a program's scope is `*.target.com` and the apex
is out of scope.

A `targets.txt` can hold anything, one per line:

```
target.com
*.api.target.com
https://app.target.com/dashboard
https://cdn.target.com/main.js
# comments are fine
```

## Scope

Scope is checked before every request, so WarpZone never wanders off your
targets. You usually do not need a scope file: if you leave `--scope` off,
scope is built from whatever target you gave and covers its subdomains.

Add `--scope scope.txt` when you want to set it by hand. One host per line. A
bare host covers that host and all of its subdomains; a `*.` prefix covers the
subdomains only and leaves the apex out. Start a line with `!` (or `-`) to
exclude a host, even when an include covers it; exclusions always win, which is
how you test all of `target.com` while staying off `blog.target.com`.

```
target.com
api.target.com
!blog.target.com
!legacy.target.com
```

Comments start with `#`. See `scope.example.txt`.

## Recon

Map the whole attack surface before you fire anything. `--recon` runs a
scope-enforced recon pipeline and bridges to the best community tools when they
are installed (and falls back to built-ins when they are not):

```bash
warpzone -d target.com --recon
warpzone -d target.com --scope scope.txt --recon
```

It chains `subfinder` + crt.sh (subdomains) -> `httpx` (live) -> `gau` /
`waybackurls` / `katana` (URLs) -> live JS -> `jsluice` (endpoints from JS),
checks every host against scope, and writes clean lists plus a readable
`recon_report.md`:

```
subdomains.txt  live_hosts.txt  urls.txt  js_files.txt
js_endpoints.txt  params.txt  interesting.txt  recon_report.md
```

`interesting.txt` is pre-filtered to the paths worth testing by hand (api,
auth, admin, upload, account, payment). No payloads are sent in recon mode.

## Run it

```bash
# passive recon: JS, endpoints, secrets, source maps, DOM-XSS leads
warpzone -d target.com

# add safe endpoint probing (status and title)
warpzone -d target.com --probe

# add active XSS: reflection probe, then confirm real DOM XSS in a browser
warpzone -d target.com --probe --xss --confirm

# start from a URL, hand param URLs to dalfox
warpzone -u https://target.com/app --xss --dalfox

# a mixed targets file, with a hand-written scope to be strict
warpzone --targets targets.txt --scope scope.txt --probe --xss
```

Tip: run the passive pass first, read the endpoints and JS it finds, then turn
on `--xss` and `--confirm` against the parts you want to test.

## Confirming DOM XSS

`--xss` tells you a parameter reflects. Reflection is not execution. `--confirm`
opens a real headless Chromium and fires a one-off token payload through every
common DOM XSS source, and only reports CONFIRMED when an alert actually runs:

- url hash (`#payload`)
- query string (`?param=payload`)
- url path
- `window.name`
- `postMessage`
- `localStorage` and `sessionStorage`
- cookies
- `document.referrer`

Confirmed hits land in `confirmed_xss.json` and at the top of the report.
All payloads are harmless `alert()` markers for authorized testing only.

### Rerun confirm without recrawling

A full crawl can take hours. When you only want to retry the browser step (say
you just installed the browser, or raised `--confirm-limit`), point
`--confirm-from` at a finished run and WarpZone skips straight to confirm:

```bash
# reuse a whole results folder (its findings.json and its scope)
warpzone --confirm-from klarna_full --confirm-limit 40 --out klarna_confirm

# or a findings.json, or a plain .txt list of URLs
warpzone --confirm-from klarna_full/findings.json
warpzone --confirm-from my_urls.txt --scope scope.txt
```

It pulls the URLs from the saved run and reuses that run's `scope_used.txt`, so
you stay in scope without re-passing `--scope`. No crawling, no bridges, just
the headless browser.

## Main options

| Flag | What it does |
| --- | --- |
| `-d DOMAIN` / `-u URL` / `--targets FILE` / `--js-list FILE` | pick the target (one of these) |
| `--recon` | recon only: subdomains, live hosts, URLs, JS endpoints, interesting paths |
| `--confirm-from PATH` | skip crawling; only confirm URLs from a saved run (folder, findings.json, or .txt) |
| `--scope FILE` | optional scope file (supports `!` exclusions); built from the target if omitted |
| `--bridges gau,waymore,katana,hakrawler` | choose crawl bridges |
| `--no-bridges` | built-in spider only |
| `--depth`, `--max-pages` | crawl depth and spider page cap |
| `--probe` | safe-GET probe of discovered endpoints |
| `--xss` | active reflection probing |
| `--confirm` | confirm DOM XSS in a headless browser |
| `--confirm-limit N` | max URLs sent to the browser (default 15) |
| `--xss-url`, `--xss-params` | aim the XSS probe precisely |
| `--xss-max-params`, `--xss-max-payloads`, `--xss-endpoints-limit` | probe budgets |
| `--dalfox` | hand param URLs to dalfox if installed |
| `--threads`, `--timeout`, `--insecure` | transport knobs |
| `--no-game` | plain output, no HUD |
| `--out DIR` | output directory |

## Output files

| File | What it is |
| --- | --- |
| `report_warpzone.md` / `.html` | the readable report |
| `findings.json` | everything, machine-readable (unredacted secrets) |
| `confirmed_xss.json` | XSS that actually fired in a browser |
| `endpoints.txt` / `endpoints_live.txt` / `endpoints_categorized.json` | endpoints, ranked and probed |
| `params.txt` | parameter names worth testing |
| `secrets.json` | secret leads with validation hints |
| `dom_xss_leads.json` | DOM-XSS leads with line numbers |
| `prettified/` | beautified JS, read these |
| `raw_js/` | original JS as served |
| `sourcemaps/` | exposed `.map` files and restored source |


