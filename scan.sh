#!/usr/bin/env bash
# =============================================================================
#  scan.sh  –  Run Trivy against the vulnerable-shopping-app and save a report
# =============================================================================
# Requirements: trivy (https://github.com/aquasecurity/trivy)
#   Install:  brew install aquasecurity/trivy/trivy
#             or: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# =============================================================================

set -euo pipefail

APP_DIR="${1:-./vulnerable-shopping-app}"
OUTPUT_DIR="${2:-./pipeline/reports}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/trivy_report_${TIMESTAMP}.json"
LATEST_LINK="${OUTPUT_DIR}/trivy_report_latest.json"

mkdir -p "$OUTPUT_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║         VulnPipeline – Trivy Scanner v1.0         ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "  Target  : $APP_DIR"
echo "  Output  : $REPORT_FILE"
echo "  Started : $(date)"
echo ""

# ── Check trivy is available ──────────────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
  echo "❌  trivy not found. Install it first:"
  echo "    brew install aquasecurity/trivy/trivy"
  echo ""
  echo "    Falling back to sample report for pipeline demo..."
  if [ -f "./pipeline/reports/sample_trivy_report.json" ]; then
    cp "./pipeline/reports/sample_trivy_report.json" "$REPORT_FILE"
    ln -sf "$(realpath "$REPORT_FILE")" "$LATEST_LINK" 2>/dev/null || cp "$REPORT_FILE" "$LATEST_LINK"
    echo "    Sample report copied to: $REPORT_FILE"
  fi
  exit 0
fi

# ── Run Trivy ─────────────────────────────────────────────────────────────────
echo "🔍  Scanning $APP_DIR/package.json for vulnerabilities..."
echo ""

trivy fs \
  --scanners vuln \
  --format json \
  --output "$REPORT_FILE" \
  --severity CRITICAL,HIGH,MEDIUM \
  --pkg-types library \
  "$APP_DIR"

# Create a symlink to the latest report
ln -sf "$(realpath "$REPORT_FILE")" "$LATEST_LINK" 2>/dev/null || cp "$REPORT_FILE" "$LATEST_LINK"

# ── Summary ───────────────────────────────────────────────────────────────────
CRITICAL=$(python3 -c "
import json, sys
with open('$REPORT_FILE') as f: d = json.load(f)
results = d.get('Results', [])
count = sum(
    1 for r in results
    for v in (r.get('Vulnerabilities') or [])
    if v.get('Severity') == 'CRITICAL'
)
print(count)
" 2>/dev/null || echo "?")

HIGH=$(python3 -c "
import json
with open('$REPORT_FILE') as f: d = json.load(f)
results = d.get('Results', [])
count = sum(
    1 for r in results
    for v in (r.get('Vulnerabilities') or [])
    if v.get('Severity') == 'HIGH'
)
print(count)
" 2>/dev/null || echo "?")

echo ""
echo "✅  Scan complete!"
echo ""
echo "   CRITICAL : $CRITICAL"
echo "   HIGH     : $HIGH"
echo "   Report   : $REPORT_FILE"
echo ""

# ── Trigger pipeline if criticals found ──────────────────────────────────────
if [ "$CRITICAL" != "0" ] && [ "$CRITICAL" != "?" ]; then
  echo "🚨  Critical vulnerabilities detected!"
  echo "    Triggering CVE remediation pipeline..."
  echo ""
  python3 ./pipeline/cve_pipeline.py --report "$REPORT_FILE"
else
  echo "✅  No critical vulnerabilities found."
fi
