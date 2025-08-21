#!/bin/bash
set -uo pipefail

# -----------------------------
# Configuration
# -----------------------------
PROJECT_DIR="$HOME/project"                     # Local path for the repository
CONFIG_DIR="$HOME/FOSShub/ort-config"
OUTPUT_DIR="$HOME/project/ort-output-$(date +%Y%m%d-%H%M%S)"
ORT_IMAGE="ghcr.io/oss-review-toolkit/ort:latest"
CERT_FILE_HOST_PATH="$HOME/certificate.pem"
CERT_FILE_DOCKER_PATH="/tmp/certificate.pem"
TRUST_STORE_PASSWORD="changeit"
BRANCH="main"
export JAVA_HOME="/opt/java/openjdk"

JAVA_TOOL_OPTIONS_VALUE="-Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks -Djavax.net.ssl.trustStorePassword=$TRUST_STORE_PASSWORD"

echo "🔍 Project directory: $PROJECT_DIR"
echo "📁 Output directory: $OUTPUT_DIR"

# -----------------------------
# Certificate check
# -----------------------------
if [ ! -f "$CERT_FILE_HOST_PATH" ]; then
  echo "❌ Certificate file not found at $CERT_FILE_HOST_PATH"
  exit 1
fi

# -----------------------------
# Ensure .ort.yml exists
# -----------------------------
if [ ! -f "$PROJECT_DIR/.ort.yml" ]; then
  echo "❌ No .ort.yml found in $PROJECT_DIR. This file is required for VCS info."
  exit 1
fi

# -----------------------------
# Create output directories
# -----------------------------
mkdir -p "$OUTPUT_DIR"/{analyzer-result,scanner-result,advisor-result,evaluator-result,report-result,syft-result,trivy-result}

# -----------------------------
# ORT Analyze
# -----------------------------
echo "===> Running ORT analyze..."
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -v "$CERT_FILE_HOST_PATH":"$CERT_FILE_DOCKER_PATH" \
  -v "$OUTPUT_DIR":/ort/data \
  -e "JAVA_HOME=$JAVA_HOME" \
  --entrypoint /bin/sh \
  "$ORT_IMAGE" -c "
    cp \"\$JAVA_HOME/lib/security/cacerts\" /ort/data/custom-cacerts.jks && \
    keytool -import -trustcacerts -keystore /ort/data/custom-cacerts.jks \
      -storepass \"$TRUST_STORE_PASSWORD\" -alias example_cert \
      -file \"$CERT_FILE_DOCKER_PATH\" -noprompt && \
    export JAVA_TOOL_OPTIONS=\"-Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks \
    -Djavax.net.ssl.trustStorePassword=$TRUST_STORE_PASSWORD\" && \
    ort analyze \
      -i /project \
      -o /ort/data/analyzer-result \
      --repository-configuration-file /project/.ort.yml
  "

ANALYZE_RESULT=$(find "$OUTPUT_DIR/analyzer-result" -type f -name "analyzer-result*.yml" | sort | tail -n 1)
[ -s "$ANALYZE_RESULT" ] && echo "✅ Analyzer result exists: $ANALYZE_RESULT" \
  || { echo "❌ Analyzer result missing or empty."; exit 1; }

# -----------------------------
# ORT Scan
# -----------------------------
echo "===> Running ORT scan..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  --package-types PROJECT \
  --project-scanners ScanCode \
  --skip-excluded \
  -o /ort/data/scanner-result

SCAN_RESULT=$(find "$OUTPUT_DIR/scanner-result" -type f -name "scan-result*.yml" | sort | tail -n 1)
[ -s "$SCAN_RESULT" ] && echo "✅ Scan result exists: $SCAN_RESULT" \
  || { echo "❌ Scan result missing or empty."; exit 1; }

# -----------------------------
# Syft SBOM generation
# -----------------------------
SYFT_OUTPUT_DIR="$OUTPUT_DIR/syft-result"
echo "===> Preparing Syft output directory..."
mkdir -p "$SYFT_OUTPUT_DIR"

echo "===> Running Syft SPDX SBOM generation with custom CA..."
docker run --rm \
  -e SYFT_CHECK_FOR_UPDATES=false \
  -v "$PROJECT_DIR":/project:ro \
  -v "$SYFT_OUTPUT_DIR":/output \
  -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem \
  -e SSL_CERT_FILE=/tmp/certificate.pem \
  ghcr.io/anchore/syft:latest \
  /project -o spdx-json=/output/sbom-spdx.json

echo "===> Running Syft CycloneDX SBOM generation with custom CA..."
docker run --rm \
  -e SYFT_CHECK_FOR_UPDATES=false \
  -v "$PROJECT_DIR":/project:ro \
  -v "$SYFT_OUTPUT_DIR":/output \
  -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem \
  -e SSL_CERT_FILE=/tmp/certificate.pem \
  ghcr.io/anchore/syft:latest \
  /project -o cyclonedx-json=/output/sbom-cdx.json

SYFT_SPX="$SYFT_OUTPUT_DIR/sbom-spdx.json"
SYFT_CDX="$SYFT_OUTPUT_DIR/sbom-cdx.json"

[ -s "$SYFT_SPX" ] && echo "✅ Syft SPDX SBOM generated: $SYFT_SPX" \
  || echo "⚠️ Syft SPDX SBOM missing or empty."

[ -s "$SYFT_CDX" ] && echo "✅ Syft CycloneDX SBOM generated: $SYFT_CDX" \
  || echo "⚠️ Syft CycloneDX SBOM missing or empty."

# -----------------------------
# Trivy Scan
# -----------------------------
TRIVY_OUTPUT_DIR="$OUTPUT_DIR/trivy-result"
mkdir -p "$TRIVY_OUTPUT_DIR"

echo "===> Running Trivy vulnerability scan (filesystem)..."
# SPDX SBOM from Trivy
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  aquasec/trivy:latest fs /project \
  --format spdx-json \
  > "$TRIVY_OUTPUT_DIR/trivy-spdx.json"

TRIVY_RESULT="$TRIVY_OUTPUT_DIR/trivy-spdx.json"
[ -s "$TRIVY_RESULT" ] && echo "✅ Trivy scan completed: $TRIVY_RESULT" \
  || echo "⚠️ Trivy scan failed or empty."

# CycloneDX SBOM from Trivy
echo "===> Running Trivy CycloneDX SBOM generation..."
# Trivy CycloneDX SBOM
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  aquasec/trivy:latest fs /project \
  --format cyclonedx \
  > "$TRIVY_OUTPUT_DIR/trivy-cdx.json"

TRIVY_CDX="$TRIVY_OUTPUT_DIR/trivy-cdx.json"
[ -s "$TRIVY_CDX" ] && echo "✅ Trivy CycloneDX SBOM generated: $TRIVY_CDX" \
  || echo "⚠️ Trivy CycloneDX SBOM missing or empty."

# -----------------------------
# ORT Advise
# -----------------------------
echo "===> Running ORT advise..."
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" advise \
  --advisors="OSV,OSSIndex" \
  --ort-file "/ort/data/scanner-result/$(basename "$SCAN_RESULT")" \
  -o /ort/data/advisor-result

ADVISE_RESULT=$(find "$OUTPUT_DIR/advisor-result" -type f -name "advisor-result*.yml" | sort | tail -n 1)
[ -s "$ADVISE_RESULT" ] && echo "✅ Advisor result exists: $ADVISE_RESULT" \
  || { echo "❌ Advisor result missing or empty."; exit 1; }

# -----------------------------
# ORT Evaluate
# -----------------------------
echo "===> Running ORT evaluate..."
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" evaluate \
  --ort-file /ort/data/advisor-result/advisor-result.yml \
  -r /home/ort/.ort/config/rules.kts \
  -o /ort/data/evaluator-result 

EVAL_RESULT=$(find "$OUTPUT_DIR/evaluator-result" -type f -name "evaluation-result*.yml" | sort | tail -n 1)
[ -s "$EVAL_RESULT" ] && echo "✅ Evaluator result exists: $EVAL_RESULT" \
  || { echo "❌ Evaluator result missing or empty."; exit 1; }

# -----------------------------
# ORT Report
# -----------------------------
echo "===> Running ORT reporter..."
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" report \
  --ort-file /ort/data/evaluator-result/$(basename "$EVAL_RESULT") \
  -o /ort/data/report-result \
  --report-formats "CycloneDX,HtmlTemplate,WebApp,PdfTemplate"

REPORT_RESULT=$(find "$OUTPUT_DIR/report-result" -type f \( -name "*.html" -o -name "*.json" \) | sort | tail -n 1)
[ -s "$REPORT_RESULT" ] && echo "✅ Report generated: $REPORT_RESULT" \
  || { echo "❌ Report generation failed or empty."; exit 1; }


# -----------------------------
# Summary
# -----------------------------
echo "🎉 ORT pipeline completed successfully!"
echo "Results:"
echo "  Analyzer:   $ANALYZE_RESULT"
echo "  Scanner:    $SCAN_RESULT"
echo "  Advisor:    $ADVISE_RESULT"
echo "  Evaluator:  $EVAL_RESULT"
echo "  Reporter:  $REPORT_RESULT"

