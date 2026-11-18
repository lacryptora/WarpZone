#!/usr/bin/env bash
#  WarpZone setup - core kit + (optionally) the strongest community bridges.
set -e

echo "=============================================="
echo "  WARPZONE setup - by Shaimaa Khattab"
echo "=============================================="

echo "[*] installing WarpZone core..."
python3 -m pip install -e ".[all]"

echo "[*] optional community bridges (install what you like):"
cat <<'BRIDGES'
  ── crawlers & archived URLs ──────────────────────────────
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/hakluke/hakrawler@latest
  pip install waymore

  ── JS superpowers ────────────────────────────────────────
  go install github.com/BishopFox/jsluice/cmd/jsluice@latest

  ── XSS browser-verified confirmation ─────────────────────
  go install github.com/hahwul/dalfox/v2@latest
BRIDGES

echo
echo "✅ Done. Try it:  warpzone --demo"
echo "   Real run:     warpzone -d target.com --scope scope.txt --probe --xss"
