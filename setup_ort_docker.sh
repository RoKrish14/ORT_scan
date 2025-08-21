#!/bin/bash
set -uo pipefail

# -----------------------------
# Configuration
# -----------------------------
PROJECT_DIR="${PROJECT_DIR:-$HOME/project}"                     # Local path for the repository
CONFIG_DIR="${CONFIG_DIR:-$HOME/FOSShub/ort-config}"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/project/ort-output-$(date +%Y%m%d-%H%M%S)}"
ORT_IMAGE="${ORT_IMAGE:-ghcr.io/oss-review-toolkit/ort:latest}"
SYFT_IMAGE="${SYFT_IMAGE:-ghcr.io/anchore/syft:latest}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
CERT_FILE_HOST_PATH="${CERT_FILE_HOST_PATH:-$HOME/certificate.pem}"
CERT_FILE_DOCKER_PATH="/tmp/certificate.pem"
TRUST_STORE_PASSWORD="${TRUST_STORE_PASSWORD:-changeit}"
BRANCH="${BRANCH:-main}"
export JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"

# Used for all JVM-based ORT steps (scan/advise/evaluate/report)
JAVA_TOOL_OPTIONS_VALUE="-Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks -Djavax.net.ssl.trustStorePassword=$TRUST_STORE_PASSWORD"

# Proxy passthrough (optional)
DOCKER_ENV=()
for v in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
  [[ -n "${!v-}" ]] && DOCKER_ENV+=(-e "$v=${!v}")
done

echo "🔍 Project directory: $PROJECT_DIR"
echo "📁 Output directory:  $OUTPUT_DIR"

# -----------------------------
# Dependency-Track Configuration
# -----------------------------
export DTRACK_URL="${DTRACK_URL:-http://localhost:8081}"
export DTRACK_PROJECT="${DTRACK_PROJECT:-MySBOMProject}"
export DTRACK_API_KEY="${DTRACK_API_KEY:-}"   # leave empty or set externally

echo "🛡️  Dependency-Track URL: $DTRACK_URL"
echo "📦 Dependency-Track project: $DTRACK_PROJECT"

# -----------------------------
# Pre-flight checks
# -----------------------------
if [ ! -f "$CERT_FILE_HOST_PATH" ]; then
  echo "❌ Certificate file not found at $CERT_FILE_HOST_PATH"
  exit 1
fi

if [ ! -f "$PROJECT_DIR/.ort.yml" ]; then
  echo "❌ No .ort.yml found in $PROJECT_DIR. This file is required for VCS info."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"/{analyzer-result,scanner-result,advisor-result,evaluator-result,report-result,syft-result,trivy-result}

# -----------------------------
# ORT Analyze (creates custom truststore)
# -----------------------------
echo "===> Running ORT analyze..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -v "$CERT_FILE_HOST_PATH":"$CERT_FILE_DOCKER_PATH":ro \
  -v "$OUTPUT_DIR":/ort/data \
  -e "JAVA_HOME=$JAVA_HOME" \
  --entrypoint /bin/sh \
  "$ORT_IMAGE" -c "
    set -euo pipefail
    CACERTS=\"\$JAVA_HOME/lib/security/cacerts\"
    [ -f \"\$CACERTS\" ] || { echo '❌ cacerts not found at' \"\$CACERTS\"; exit 1; }
    cp \"\$CACERTS\" /ort/data/custom-cacerts.jks
    keytool -import -trustcacerts -keystore /ort/data/custom-cacerts.jks \
      -storepass \"$TRUST_STORE_PASSWORD\" -alias example_cert \
      -file \"$CERT_FILE_DOCKER_PATH\" -noprompt
    export JAVA_TOOL_OPTIONS='$JAVA_TOOL_OPTIONS_VALUE'
    ort analyze \
      -i /project \
      -o /ort/data/analyzer-result \
      --repository-configuration-file /project/.ort.yml
  "

ANALYZE_RESULT="$(find "$OUTPUT_DIR/analyzer-result" -type f -name 'analyzer-result*.yml' | sort | tail -n 1 || true)"
[ -s "${ANALYZE_RESULT:-}" ] && echo "✅ Analyzer result: $ANALYZE_RESULT" || { echo "❌ Analyzer result missing or empty."; exit 1; }

# -----------------------------
# ORT Scan (project-only to avoid long package scans)
# -----------------------------
echo "===> Running ORT scan..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "${DOCKER_ENV[@]}" \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  --package-types PROJECT \
  --project-scanners ScanCode \
  --skip-excluded \
  -o /ort/data/scanner-result

SCAN_RESULT="$(find "$OUTPUT_DIR/scanner-result" -type f -name 'scan-result*.yml' | sort | tail -n 1 || true)"
[ -s "${SCAN_RESULT:-}" ] && echo "✅ Scan result: $SCAN_RESULT" || { echo "❌ Scan result missing or empty."; exit 1; }

# -----------------------------
# Syft SBOM generation
# -----------------------------
SYFT_OUTPUT_DIR="$OUTPUT_DIR/syft-result"
echo "===> Running Syft SPDX & CycloneDX (with custom CA)..."
docker run --rm -u "$(id -u):$(id -g)" \
  -e SYFT_CHECK_FOR_UPDATES=false \
  -v "$PROJECT_DIR":/project:ro \
  -v "$SYFT_OUTPUT_DIR":/output \
  -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem:ro \
  -e SSL_CERT_FILE=/tmp/certificate.pem \
  "$SYFT_IMAGE" /project -o spdx-json=/output/sbom-spdx.json

docker run --rm -u "$(id -u):$(id -g)" \
  -e SYFT_CHECK_FOR_UPDATES=false \
  -v "$PROJECT_DIR":/project:ro \
  -v "$SYFT_OUTPUT_DIR":/output \
  -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem:ro \
  -e SSL_CERT_FILE=/tmp/certificate.pem \
  "$SYFT_IMAGE" /project -o cyclonedx-json=/output/sbom-cdx.json

SYFT_SPX="$SYFT_OUTPUT_DIR/sbom-spdx.json"
SYFT_CDX="$SYFT_OUTPUT_DIR/sbom-cdx.json"
[ -s "$SYFT_SPX" ] && echo "✅ Syft SPDX:       $SYFT_SPX" || echo "⚠️ Syft SPDX missing."
[ -s "$SYFT_CDX" ] && echo "✅ Syft CycloneDX:  $SYFT_CDX" || echo "⚠️ Syft CycloneDX missing."

# -----------------------------
# Trivy SBOM generation
# -----------------------------
TRIVY_OUTPUT_DIR="$OUTPUT_DIR/trivy-result"
mkdir -p "$TRIVY_OUTPUT_DIR"

echo "===> Running Trivy SPDX..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  "$TRIVY_IMAGE" fs /project --format spdx-json \
  > "$TRIVY_OUTPUT_DIR/trivy-spdx.json"

TRIVY_SPX="$TRIVY_OUTPUT_DIR/trivy-spdx.json"
[ -s "$TRIVY_SPX" ] && echo "✅ Trivy SPDX:      $TRIVY_SPX" || echo "⚠️ Trivy SPDX missing."

echo "===> Running Trivy CycloneDX..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  "$TRIVY_IMAGE" fs /project --format cyclonedx \
  > "$TRIVY_OUTPUT_DIR/trivy-cdx.json"

TRIVY_CDX="$TRIVY_OUTPUT_DIR/trivy-cdx.json"
[ -s "$TRIVY_CDX" ] && echo "✅ Trivy CycloneDX: $TRIVY_CDX" || echo "⚠️ Trivy CycloneDX missing."

# -----------------------------
# ORT Advise (retry for transient OSV timeouts)
# -----------------------------
echo "===> Running ORT advise..."
max_tries=3
try=1
until docker run --rm -u "$(id -u):$(id -g)" \
    -v "$PROJECT_DIR":/project \
    -v "$OUTPUT_DIR":/ort/data \
    -v "$CONFIG_DIR":/home/ort/.ort/config \
    -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
    "${DOCKER_ENV[@]}" \
    "$ORT_IMAGE" advise \
    --advisors="OSV,OSSIndex" \
    --ort-file "/ort/data/scanner-result/$(basename "$SCAN_RESULT")" \
    -o /ort/data/advisor-result
do
  if (( try >= max_tries )); then
    echo "❌ ORT advise failed after $max_tries attempts."
    exit 1
  fi
  echo "⚠️  ORT advise failed (attempt $try). Retrying in $((try*10))s…"
  sleep $((try*10))
  ((try++))
done

ADVISE_RESULT="$(find "$OUTPUT_DIR/advisor-result" -type f -name 'advisor-result*.yml' | sort | tail -n 1 || true)"
[ -s "${ADVISE_RESULT:-}" ] && echo "✅ Advisor result: $ADVISE_RESULT" || { echo "❌ Advisor result missing or empty."; exit 1; }

# -----------------------------
# ORT Evaluate
# -----------------------------
echo "===> Running ORT evaluate..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "$ORT_IMAGE" evaluate \
  --ort-file "/ort/data/advisor-result/$(basename "$ADVISE_RESULT")" \
  -r /home/ort/.ort/config/rules.kts \
  -o /ort/data/evaluator-result

EVAL_RESULT="$(find "$OUTPUT_DIR/evaluator-result" -type f -name 'evaluation-result*.yml' | sort | tail -n 1 || true)"
[ -s "${EVAL_RESULT:-}" ] && echo "✅ Evaluator result: $EVAL_RESULT" || { echo "❌ Evaluator result missing or empty."; exit 1; }

# -----------------------------
# ORT Report
# -----------------------------
echo "===> Running ORT reporter..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "$ORT_IMAGE" report \
  --ort-file "/ort/data/evaluator-result/$(basename "$EVAL_RESULT")" \
  -o /ort/data/report-result \
  --report-formats "CycloneDX,HtmlTemplate,WebApp,PdfTemplate"

# Capture any generated HTML / JSON and the CycloneDX from ORT
REPORT_RESULT="$(find "$OUTPUT_DIR/report-result" -type f \( -name '*.html' -o -name '*.json' \) | sort | tail -n 1 || true)"
ORT_CDX="$(find "$OUTPUT_DIR/report-result" -type f -name '*cyclonedx*.json' | sort | tail -n 1 || true)"

[ -s "${REPORT_RESULT:-}" ] && echo "✅ Report artifact: $REPORT_RESULT" || { echo "❌ Report generation failed or empty."; exit 1; }
[ -s "${ORT_CDX:-}" ] && echo "✅ ORT CycloneDX:   $ORT_CDX" || echo "⚠️ ORT CycloneDX not found (report format may have changed)."

# -----------------------------
# Summary
# -----------------------------
cat <<EOF
🎉 ORT pipeline completed successfully!

Results:
  Analyzer:         $ANALYZE_RESULT
  Scanner:          $SCAN_RESULT
  Advisor:          $ADVISE_RESULT
  Evaluator:        $EVAL_RESULT
  Report (sample):  $REPORT_RESULT

SBOMs:
  ORT CycloneDX:    ${ORT_CDX:-<none>}
  Syft SPDX:        $SYFT_SPX
  Syft CycloneDX:   $SYFT_CDX
  Trivy SPDX:       $TRIVY_SPX
  Trivy CycloneDX:  $TRIVY_CDX
EOF

# -----------------------------
# Dependency-Track Upload
# -----------------------------
if [[ -n "${DTRACK_URL:-}" && -n "${DTRACK_API_KEY:-}" && -n "${DTRACK_PROJECT:-}" ]]; then
  echo "===> Uploading SBOMs to Dependency-Track at $DTRACK_URL"
  # Choose the best available CycloneDX first (ORT, then Syft, then Trivy)
  SBOMS_TO_UPLOAD=()
  [[ -s "${ORT_CDX:-}"  ]] && SBOMS_TO_UPLOAD+=("$ORT_CDX")
  [[ -s "${SYFT_CDX:-}" ]] && SBOMS_TO_UPLOAD+=("$SYFT_CDX")
  [[ -s "${TRIVY_CDX:-}" ]] && SBOMS_TO_UPLOAD+=("$TRIVY_CDX")

  if (( ${#SBOMS_TO_UPLOAD[@]} == 0 )); then
    echo "⚠️  No CycloneDX SBOMs found to upload."
  else
    for sbom in "${SBOMS_TO_UPLOAD[@]}"; do
      echo "📤 Uploading $(basename "$sbom")..."
      curl -sS -X POST "$DTRACK_URL/api/v1/bom" \
        -H "X-Api-Key: $DTRACK_API_KEY" \
        -H "Content-Type: multipart/form-data" \
        -F "projectName=$DTRACK_PROJECT" \
        -F "projectVersion=1.0.0" \
        -F "autoCreate=true" \
        -F "bom=@$sbom" \
        && echo "✅ Uploaded: $sbom" || { echo "❌ Upload failed: $sbom"; exit 1; }
    done
  fi
else
  echo "⚠️  Dependency-Track upload skipped (missing URL/API key/project)"
fi

echo "🎉 ORT pipeline completed. All outputs are in $OUTPUT_DIR"

