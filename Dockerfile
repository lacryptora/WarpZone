# WarpZone - JS recon & XSS arsenal
# Created by Shaimaa Khattab
FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir ".[all]"

# Want the Go bridges (gau/katana/httpx/hakrawler/jsluice/dalfox) baked in?
# Uncomment:
# RUN apt-get update && apt-get install -y --no-install-recommends golang git ca-certificates \
#     && go install github.com/lc/gau/v2/cmd/gau@latest \
#     && go install github.com/projectdiscovery/katana/cmd/katana@latest \
#     && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
#     && go install github.com/hakluke/hakrawler@latest \
#     && go install github.com/BishopFox/jsluice/cmd/jsluice@latest \
#     && go install github.com/hahwul/dalfox/v2@latest \
#     && rm -rf /var/lib/apt/lists/*

# Mount results somewhere useful:
#   docker run --rm -v "$PWD/results:/results" warpzone \
#       -d target.com --scope /results/scope.txt --probe --xss --out /results/out
ENTRYPOINT ["warpzone"]
CMD ["--demo"]
