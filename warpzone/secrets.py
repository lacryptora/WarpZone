"""World 1-3 (SECRET VAULTS, part A): secrets & API keys hidden in JS.

Prefix-anchored, high/medium-confidence pattern database (35+ patterns) plus
a generic literal scanner and a high-entropy blob finder for the unknown-unknowns.

Every finding is a LEAD: validate it yourself (see the hint), never USE a key.
Report display redacts values; the full value is only in secrets.json.
"""
import re

from . import core

# (name, regex, confidence, hint)
PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "high",
     "Confirm ownership via the account owner; a live key = critical"),
    ("AWS MWS Auth Token", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high", "Amazon MWS auth token"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high",
     "Test which Google APIs the key can reach (maps/cloud)"),
    ("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "high", "Short-lived OAuth token — check freshness"),
    ("Google OAuth Client ID", r"[0-9]{10,}-[0-9a-z]{32}\.apps\.googleusercontent\.com", "medium", "Public client ids are common; look for a paired secret"),
    ("GCP Service Account JSON", r'"type"\s*:\s*"service_account"', "high", "Full SA key = account takeover"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{36,255}", "high", "ghp_=PAT, gho_=oauth, ghs_=server, ghu_=user, ghr_=refresh"),
    ("GitLab PAT", r"glpat-[0-9A-Za-z\-_]{20,}", "high", "Validate via GitLab API /user"),
    ("NPM Token", r"npm_[0-9A-Za-z]{36}", "high", "npm publish/read token"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "high", "xoxb=bot, xoxp=user, xoxa=app"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{10,}", "high", "Post a benign test message to confirm"),
    ("Stripe Live Secret", r"sk_live_[0-9a-zA-Z]{24,}", "high", "CRITICAL: live Stripe secret key"),
    ("Stripe Restricted", r"rk_live_[0-9a-zA-Z]{24,}", "high", "Live restricted key — check its permissions"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}", "medium", "Publishable keys ship in JS by design; note context"),
    ("SendGrid Key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "high", "Validate via SendGrid API scopes call"),
    ("Twilio SID", r"AC[0-9a-fA-F]{32}", "high", "Account SID — look for the paired auth token"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high", "Twilio API key"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}", "medium", "Mailgun private key"),
    ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "high", "Graph API access token"),
    ("Firebase FCM Key", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "high", "Cloud Messaging server key — can push to any device"),
    ("Firebase RTDB URL", r"https://[a-z0-9\-]+\.firebaseio(?:\.com|\.io)[^\"'`\s]*", "high", "Try /.json read on an authorized test project"),
    ("Heroku API Key", r"hvs\.[0-9a-fA-F]{32}", "high", "Heroku vault key"),
    ("Telegram Bot Token", r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}", "high", "getMe on the token confirms the bot"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{10,}/[A-Za-z0-9_-]+", "high", "Execute a benign ping to confirm"),
    ("Square Token", r"sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}", "high", "Square access/OAuth secret"),
    ("PayPal Braintree", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "high", "Braintree production access token"),
    ("Shopify Token", r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}", "high", "shpat_=admin API token"),
    ("Sentry Auth Token", r"(?i)sentry['\"]?\s*[:=]\s*['\"][0-9a-f]{32}", "medium", "Sentry DSN/token — org issues readable"),
    ("Datadog Key", r"(?i)(?:dd_api_key|datadog[_-]?api[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-f0-9]{32}", "medium", "Datadog API key"),
    ("New Relic Key", r"NRII-[0-9a-zA-Z\-]{32}|NRAK-[0-9A-Z]{26}", "high", "New Relic insight/api key"),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----", "high", "CRITICAL: full private key material"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium",
     "Decode on jwt.io: check alg=none, kid confusion, long exp"),
    ("Basic Auth Header", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/=]{16,}", "high", "Base64 creds — decode locally, never replay"),
    ("Generic api_key/secret", r"(?i)(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{16,}['\"]", "medium", "Unkeyed literal — match the name to a vendor"),
    ("Password literal", r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", "medium", "Hardcoded password — often a default/dev cred"),
    ("AWS S3 Bucket URL", r"https://[a-z0-9._-]+\.s3[.-]?[a-z0-9-]*\.?amazonaws\.com[^\"'`\s]*", "medium", "Check anonymous listing/read on the bucket"),
    ("Internal IP", r"(?<![\d.])(?:10\.\d{1,3}|192\.168\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}(?!\d)", "low", "Internal host — map the network layout"),
    ("Hardcoded Host:Port", r"https?://[a-z0-9._-]+:(?:[0-9]{2,5})/?", "low", "Non-standard service port — probe it"),
]

ENTROPY_RE = re.compile(r"""['\"]([A-Za-z0-9+/=_\-]{32,})['\"]""")
KNOWN_PREFIXES = ("eyJ", "AKIA", "AIza", "SG\\.", "ghp_", "xox", "sk_live", "pk_live",
                  "rk_live", "npm_", "glpat-", "hvs\\.", "shp", "sq0", "AAAA")


def mine(text, url, entropy_threshold=4.2, max_entropy_hits=10):
    """Extract secret leads from one JS file's text."""
    findings = []
    seen = set()
    for name, pat, conf, hint in PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"type": name, "confidence": conf,
                             "match": val[:200], "file": url, "hint": hint,
                             "redacted": core.redact(val)})
    # high-entropy opaque blobs the patterns don't know about
    known_vals = {f["match"] for f in findings}
    hits = 0
    for m in ENTROPY_RE.finditer(text):
        val = m.group(1)
        if hits >= max_entropy_hits or val in known_vals:
            continue
        if any(val.startswith(p.rstrip("\\")) for p in ("eyJ", "AKIA", "AIza", "ghp_")):
            continue
        if core.entropy(val) >= entropy_threshold and not val.isdigit():
            hits += 1
            findings.append({"type": "High-entropy string", "confidence": "low",
                             "match": val[:200], "file": url,
                             "hint": "Opaque blob — could be key/salt/encrypted config; triage by hand",
                             "redacted": core.redact(val)})
    return findings


def dedupe(all_findings):
    seen, out = set(), []
    for f in all_findings:
        key = (f["type"], f["match"], f["file"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
