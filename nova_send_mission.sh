#!/bin/bash
# Send a mission from Termux to Codespace via GitHub

REPO="Informant254/Nova-arsenal"
TYPE="${1:-audit}"
TARGET="${2:-https://github.com/python/cpython.git}"

echo "{\"type\":\"$TYPE\",\"target\":\"$TARGET\",\"timestamp\":\"$(date -Iseconds)\"}" > mission.json

git add mission.json
git commit -m "Mission: $TYPE $TARGET"
git push origin main

echo "🚀 Mission sent to Codespace!"
echo "   Type: $TYPE"
echo "   Target: $TARGET"
echo ""
echo "The Codespace will execute this and push results back."
echo "Check results in 30 seconds with:"
echo "   git pull && cat result.json"
