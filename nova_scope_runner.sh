#!/bin/bash

if [ -z "$1" ]; then
    echo "❌ Usage: ./nova_scope_runner.sh <targets.txt> [delay]"
    exit 1
fi

TARGET_FILE=$1
DELAY=${2:-0.2}

if [ ! -f "$TARGET_FILE" ]; then
    echo "❌ File '$TARGET_FILE' not found."
    exit 1
fi

echo "🦅 NOVA MASS SCOPE RUNNER"
echo "=========================="
echo "📁 Targets: $TARGET_FILE"
echo "⏱️  Delay: ${DELAY}s"
echo ""

while IFS= read -r line || [ -n "$line" ]; do
    target=$(echo "$line" | xargs)
    [[ -z "$target" || "$target" == \#* ]] && continue
    [[ ! "$target" =~ ^https?:// ]] && target="https://$target"

    echo "📡 Scanning: $target"
    python3 nova_live_hunt.py "$target" "$DELAY"
    echo "---"
done < "$TARGET_FILE"

echo "🦅 All targets scanned."
