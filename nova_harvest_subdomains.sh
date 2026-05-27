#!/bin/bash
# Nova Subdomain Harvester - crt.sh Certificate Transparency
# Usage: ./nova_harvest_subdomains.sh notion.so targets.txt

DOMAIN="${1:-notion.so}"
OUTPUT="${2:-targets.txt}"

echo "🦅 NOVA SUBDOMAIN HARVESTER"
echo "=========================="
echo "🎯 Domain: *.$DOMAIN"
echo "📡 Querying crt.sh Certificate Transparency logs..."
echo ""

# Query crt.sh and extract subdomains
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
    python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        name = entry.get('name_value', '')
        # Handle wildcards and multi-name entries
        for n in name.split('\\n'):
            n = n.strip().lstrip('*.')
            if n and '$DOMAIN' in n:
                names.add(n)
    for name in sorted(names):
        print(name)
except:
    print('Error parsing crt.sh response')
" | sort -u > "$OUTPUT"

COUNT=$(wc -l < "$OUTPUT")
echo ""
echo "✅ Harvested $COUNT unique subdomains"
echo "📁 Saved to: $OUTPUT"
echo ""
echo "🔍 Top subdomains:"
head -10 "$OUTPUT"
echo ""
echo "🦅 Ready to launch: ./nova_scope_runner.sh $OUTPUT 0.3"
