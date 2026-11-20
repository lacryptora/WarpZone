#!/usr/bin/env bash
# WarpZone setup: core kit, plus the optional tools that make it stronger.
set -e

echo "=============================================="
echo "  WARPZONE setup - by Shaimaa Khattab"
echo "=============================================="

echo "[*] installing WarpZone core (plus HUD, beautifier, browser confirm)..."
python3 -m pip install -e ".[all]"

echo "[*] installing the headless browser for --confirm..."
python3 -m playwright install chromium || echo "    (skip for now; run 'playwright install chromium' later)"

echo "[*] optional community bridges (install what you like):"
cat <<'BRIDGES'
  -- crawlers and archived URLs ----------------------------
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/hakluke/hakrawler@latest
  pip install waymore

  -- XSS confirmation --------------------------------------
  go install github.com/hahwul/dalfox/v2@latest
BRIDGES

echo
echo "Done. Try a run:"
echo "   warpzone -d target.com --scope scope.txt --probe --xss --confirm"
