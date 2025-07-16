#!/bin/bash
set -e

# -----------------------------
# CONFIGURATION
# -----------------------------

PROJECT_DIR="./emoji-java"
REPORT_DIR="./reports"
ORT_DIR="./ort-results"
ORT_GLOBAL_CONFIG_DIR="./ort/.ort/config"
REPOSITORY_CONFIG_FILE="repository.yml"

mkdir -p "$REPORT_DIR" "$ORT_DIR"

# -----------------------------
# TOOL VERSION CHECKS (Docker)
# -----------------------------

echo "---"
echo "✅ Tool Versions:"
docker run --rm anchore/syft:latest version
docker run --rm aquasec/trivy:latest version
docker run --rm \
  -v "$(pwd)":/workspace \
  ort-cli \
  --version || echo "❌ ORT image not found yet (will build below)."

# -----------------------------
# BUILD ORT DOCKER IMAGE (if not already)
# -----------------------------

if [ -z "$(docker images -q ort-cli)" ]; then
  echo "---"
  echo "🐳 Building ORT Docker image..."
  docker build -t ort-cli - <<EOF
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /opt/ort
RUN apk add --no-cache curl git bash && \
    curl -s https://api.github.com/repos/oss-review-toolkit/ort/releases/latest \\
    | grep "browser_download_url.*ort" \\
    | grep -v ".asc" \\
    | cut -d '"' -f 4 \\
    | xargs curl -Lo ort && chmod +x ort
ENTRYPOINT ["./ort"]
EOF
  echo "✅ ORT Docker image built as 'ort-cli'"
fi

# -----------------------------
# SYFT - Generate SBOM
# -----------------------------

echo "---"
echo "📦 Generating SBOM with Syft..."
docker run --rm \
  -v "$(pwd)/$PROJECT_DIR":/project \
  -v "$(pwd)/$REPORT_DIR":/output \
  anchore/syft:latest dir:/project -o spdx-json > "$REPORT_DIR/sbom.spdx.json"
echo "✅ SBOM written to $REPORT_DIR/sbom.spdx.json"

# -----------------------------
# TRIVY - Vulnerability Scan
# -----------------------------

echo "---"
echo "🛡️ Running Trivy scan..."
docker run --rm \
  -v "$(pwd)/$PROJECT_DIR":/project \
  -v "$(pwd)/$REPORT_DIR":/output \
  aquasec/trivy:latest fs /project --format json --output /output/trivy-report.json
echo "✅ Trivy report written to $REPORT_DIR/trivy-report.json"

# -----------------------------
# ORT - Full Pipeline via Docker
# -----------------------------

echo "---"
echo "🔬 Running ORT pipeline..."

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  ort-cli analyze \
    -i "$PROJECT_DIR" \
    -o "$ORT_DIR" \
    -f JSON \
    --repository-configuration-file "$REPOSITORY_CONFIG_FILE"

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  ort-cli scan \
    -i "$ORT_DIR/analyzer-result.json" \
    -o "$ORT_DIR" \
    --skip-excluded

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  ort-cli evaluate \
    -i "$ORT_DIR/evaluator-input.yml" \
    -o "$ORT_DIR" \
    --rules "$ORT_GLOBAL_CONFIG_DIR/rules.kts" \
    --severity-threshold "ERROR"

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  ort-cli report \
    -i "$ORT_DIR/evaluator-result.yml" \
    -o "$REPORT_DIR" \
    -f WebApp,StaticHtml,SpdxDocument

echo "✅ ORT reports generated in $REPORT_DIR"
echo "---"
echo "🎉 OSS Review pipeline complete!"
