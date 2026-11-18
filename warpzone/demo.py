"""The WarpZone demo world: a deliberately vulnerable mock app (stdlib only).

`warpzone --demo` boots this on 127.0.0.1, generates a scope file, and runs
the full pipeline against it — perfect for testing, showcases and learning.
Everything in here is FAKE: keys are documented example values, nothing real.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

APP_JS = r"""
// demo app.js — minified on purpose to exercise the prettifier
!function(){var api={users:"/api/v1/users?id=1",orders:`/api/v1/orders/${orderId}`,
profile:"/api/v1/profile/"+userId,upload:"/upload/avatar",admin:"/admin/panel",
graphql:"/graphql",health:"/actuator/health",partner:"https://api.partner.example/v2/lookup"};
window.WZ=api;
fetch(api.users).then(r=>r.json()).then(function(d){var box=document.getElementById("out");
box.innerHTML="<b>"+d.name+"</b>";});
document.addEventListener("message",function(e){document.getElementById("chat").innerHTML=e.data;});
window.addEventListener("hashchange",function(){document.getElementById("hashbox").innerHTML=location.hash.slice(1);});
var q=location.search.slice(1);document.write("<div class='q'>"+q+"</div>");
setTimeout(window.name,3000);
axios.get("config/app-settings.json").then(function(r){window.SETTINGS=r.data});
var el=document.getElementById("go");el&&el.setAttribute("onclick",location.hash.slice(1));
window.open(decodeURIComponent(location.hash.slice(2)),"_blank");
}();
"""

UTILS_JS = r"""
// demo utils.js
function runUserInput(){var input=location.search.slice(1);eval(decodeURIComponent(input));}
function render(name){var t=document.URL.split("#")[1]||"";var el=document.getElementById("t");el.outerHTML="<h1>"+t+"</h1>";}
new Function("a","return a")();
var handler=function(ev){insertAdjacentHTML2(ev.data)};
"""

VAULT_JS = r"""
// demo vault.js — FAKE credentials, publicly documented example values only
var awsKey="AKIAIOSFODNN7EXAMPLE";
var gKey="AIzaSyDUMMY_EXAMPLE_KEY_NOT_REAL_0123456789abcd";
var gh="ghp_WarpZoneDemoToken00000000000000000000";
var slack="https://hooks.slack.com/services/T00000000/B00000000/WarpZoneDemoHook00000000";
var jwt="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3YXJwem9uZSJ9.WarpZoneDemoSig00000000000";
var tbot="123456789:AAExample_Telegram_Bot_Token_00000000000";
var fb="https://warpzone-demo.firebaseio.com/.json";
var cfg={api_key:"9f8e7d6c5b4a3928170f0e1d2c3b4a5",password:"P@ssw0rd-Demo!"};
var pk="-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKGBHWarpZoneFakeKeyMaterial00000000\n-----END RSA PRIVATE KEY-----";
"""

CHUNK_JS = r"""console.log("bundled chunk");//# sourceMappingURL=chunk.9f2a1.js.map
"""

CHUNK_MAP = json.dumps({
    "version": 3,
    "file": "chunk.9f2a1.js",
    "sourceRoot": "",
    "sources": ["src/original/chunk-source.ts"],
    "names": [],
    "mappings": "AAAA",
    "sourcesContent": ["// ORIGINAL SOURCE LEAKED VIA .MAP\nexport const secretLogic = () => 'internal-only algorithm';\n"],
})

INDEX_HTML = """<!doctype html><html><head><title>WarpZone Demo World</title></head>
<body><h1>WarpZone Demo World 1-1</h1>
<script src="/app.js"></script><script src="/utils.js"></script>
<script src="/vault.js"></script><script src="/chunk.9f2a1.js"></script>
<p><a href="/search?q=hello+world">search page</a></p>
<p><a href="/admin/panel">admin panel</a></p>
<p><a href="/api/v1/users?id=1">users api</a></p>
<div id="out"></div><div id="hashbox"></div></body></html>"""

SEARCH_HTML = """<!doctype html><html><head><title>Demo Search</title></head>
<body><h1>Search results</h1>
<div class="query">You searched for: %(q)s</div>
<input type="text" value="%(q)s" name="q">
<p>No results. Try again!</p></body></html>"""

ADMIN_HTML = """<!doctype html><html><head><title>Admin Panel</title></head>
<body><h1>Admin Panel (demo)</h1><p>Nothing here but goombas.</p></body></html>"""

ROUTES = {
    "/": ("text/html; charset=utf-8", INDEX_HTML),
    "/app.js": ("application/javascript", APP_JS),
    "/utils.js": ("application/javascript", UTILS_JS),
    "/vault.js": ("application/javascript", VAULT_JS),
    "/chunk.9f2a1.js": ("application/javascript", CHUNK_JS),
    "/chunk.9f2a1.js.map": ("application/json", CHUNK_MAP),
    "/admin/panel": ("text/html; charset=utf-8", ADMIN_HTML),
    "/api/v1/users": ("application/json", json.dumps({"id": 1, "name": "Mario"})),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/search":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = SEARCH_HTML % {"q": q}
        elif p in ROUTES:
            body = ROUTES[p][1]
        else:
            self.send_error(404)
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ROUTES.get(p, ("text/html; charset=utf-8", ""))[0])
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep the terminal clean for the HUD
        pass


def start_server(port=0):
    """Boot the demo world. Returns (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{server.server_port}"
