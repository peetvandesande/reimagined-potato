#!/usr/bin/env bash
# Helper to build the frontend Docker image with optional override for REACT_APP_* build args
set -euo pipefail
API_BASE=${REACT_APP_API_BASE:-http://localhost:5000}
WS_BASE=${REACT_APP_WS_BASE:-ws://localhost:5000}
FRONTEND_ORIGIN=${REACT_APP_FRONTEND_ORIGIN:-http://localhost:3000}

docker build \
  --build-arg REACT_APP_API_BASE="$API_BASE" \
  --build-arg REACT_APP_WS_BASE="$WS_BASE" \
  --build-arg REACT_APP_FRONTEND_ORIGIN="$FRONTEND_ORIGIN" \
  -t reimagined-potato-frontend ./frontend
