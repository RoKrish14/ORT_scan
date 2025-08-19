#!/bin/bash
set -euo pipefail

# -----------------------------
# Configuration
# -----------------------------
PROJECT_DIR="$HOME/project"
CONFIG_DIR="$HOME/FOSShub/ort-config"
OUTPUT_DIR="$HOME/project/ort-output-$(date +%Y%m%d-%H%M%S)"
ORT_IMAGE="ghcr.io/oss-review-toolkit/ort:latest"
CERT_FILE_HOST_PATH="$HOME/certificate.pem"
CERT_FILE_DOCKER_PATH="/tmp/certificate.pem"
TRUST_STORE_PASSWORD="changeit"
BRANCH="main"
export JAVA_HOME="/opt/java/openjdk"

# -----------------------------
# Dependency-Track Configuration
# -----------------------------
export DTRACK_URL="${DTRACK_URL:-http://localhost:8081}"
export DTRACK_PROJECT="${DTRACK_PROJECT:-MySBOMProject}"

echo "🔍 Project directory: $PROJECT_DIR"
echo "📁 Output directory: $OUTPUT_DIR"
echo "🛡️  Dependency-Track URL: $DTRACK_URL"
echo "📦 Dependency-Track project: $DTRACK_PROJECT"

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
    ort analyze -i /project -o /ort/data/analyzer-result \
      --repository-configuration-file /project/.ort.yml
  "

ANALYZE_RESULT="$OUTPUT_DIR/analyzer-result/analyzer-result.yml"
[ -s "$ANALYZE_RESULT" ] && echo "✅ Analyzer result exists: $ANALYZE_RESULT" || { echo "❌ Analyzer result missing or empty."; exit 1; }

# -----------------------------
# ORT Scan
# -----------------------------
echo "===> Running ORT scan..."
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  -o /ort/data/scanner-result

SCAN_RESULT="$OUTPUT_DIR/scanner-result/scan-result.yml"
[ -s "$SCAN_RESULT" ] && echo "✅ Scan result exists: $SCAN_RESULT" || { echo "❌ Scan result missing or empty."; exit 1; }

# -----------------------------
# Syft SBOM generation
# -----------------------------
SYFT_OUTPUT_DIR="$OUTPUT_DIR/syft-result"
mkdir -p "$SYFT_OUTPUT_DIR"

echo "===> Running Syft SPDX SBOM..."
docker run --rm \
  -e SYFT_CHECK_FOR_UPDATES=false \
  -v "$PROJECT_DIR":/project:ro \
  -v "$SYFT_OUTPUT_DIR":/output \
  -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem \
  -e SSL_CERT_FILE=/tmp/certificate.pem \
  ghcr.io/anchore/syft:latest \
  /project -o spdx-json=/output/sbom-spdx.json

echo "===> Running Syft CycloneDX SBOM..."
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

# -----------------------------
# Trivy Scan
# -----------------------------
TRIVY_OUTPUT_DIR="$OUTPUT_DIR/trivy-result"
mkdir -p "$TRIVY_OUTPUT_DIR"

echo "===> Running Trivy SPDX SBOM..."
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  aquasec/trivy:latest fs /project \
  --format spdx-json \
  > "$TRIVY_OUTPUT_DIR/trivy-spdx.json"

echo "===> Running Trivy CycloneDX SBOM..."
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$TRIVY_OUTPUT_DIR":/trivy \
  aquasec/trivy:latest fs /project \
  --format cyclonedx \
  > "$TRIVY_OUTPUT_DIR/trivy-cdx.json"

TRIVY_RESULT="$TRIVY_OUTPUT_DIR/trivy-spdx.json"
TRIVY_CDX="$TRIVY_OUTPUT_DIR/trivy-cdx.json"

# -----------------------------
# ORT Advise
# -----------------------------
echo "===> Running ORT advise..."
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" advise \
  --advisors="OSV,OSSIndex,VulnerableCode" \
  --ort-file "/ort/data/scanner-result/$(basename "$SCAN_RESULT")" \
  -o /ort/data/advisor-result

ADVISE_RESULT="$OUTPUT_DIR/advisor-result/advisor-result.yml"

# -----------------------------
# ORT Evaluate
# -----------------------------
echo "===> Running ORT evaluate..."
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" evaluate \
  --ort-file "/ort/data/advisor-result/$(basename "$ADVISE_RESULT")" \
  -r /home/ort/.ort/config/rules.kts \
  -o /ort/data/evaluator-result 

EVAL_RESULT="$OUTPUT_DIR/evaluator-result/evaluation-result.yml"

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

ORT_CDX="$OUTPUT_DIR/report-result/scan-report.cyclonedx.json"

# -----------------------------
# Dependency-Track Upload
# -----------------------------
if [[ -n "$DTRACK_URL" && -n "$DTRACK_API_KEY" && -n "$DTRACK_PROJECT" ]]; then
  echo "===> Uploading SBOMs to Dependency-Track at $DTRACK_URL"
  for sbom in "$ORT_CDX" "$SYFT_CDX" "$TRIVY_CDX"; do
    if [ -s "$sbom" ]; then
      echo "📤 Uploading $(basename "$sbom")..."
      curl -s -X POST "$DTRACK_URL/api/v1/bom" \
        -H "X-Api-Key: $DTRACK_API_KEY" \
        -H "Content-Type: multipart/form-data" \
        -F "projectName=$DTRACK_PROJECT" \
        -F "projectVersion=1.0.0" \
        -F "autoCreate=true" \
        -F "bom=@$sbom" \
        && echo "✅ Uploaded: $sbom"
    fi
  done
else
  echo "⚠️  Dependency-Track upload skipped (missing URL/API key/project)"
fi

echo "🎉 ORT pipeline completed. All outputs are in $OUTPUT_DIR"
