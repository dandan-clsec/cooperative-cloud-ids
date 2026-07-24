#!/bin/bash
# Download the full Emerging Threats Open ruleset into the shared rules dir.
# Optional: the framework ships with curated local.rules that cover the three
# evaluated attack classes, but this pulls the complete community ruleset.
set -euo pipefail

RULES_DIR="$(cd "$(dirname "$0")/../rules" && pwd)"
ET_URL="https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"

echo "[*] Fetching Emerging Threats Open ruleset -> ${RULES_DIR}/emerging-all.rules"
curl -fsSL "${ET_URL}" -o "${RULES_DIR}/emerging-all.rules"

echo "[*] Done. To load it, add 'emerging-all.rules' to suricata rule-files"
echo "    and include it from snort.lua, then restart the engines."
