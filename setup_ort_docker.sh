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

# -----------------------------
# DETECT DOCKER ARCHITECTURE & BUILD ORT IMAGE
# -----------------------------

echo "---"
echo "🧠 Detecting Docker runtime architecture..."
DOCKER_ARCH=$(docker run --rm alpine uname -m)

case "$DOCKER_ARCH" in
  x86_64)
    ORT_BINARY="ort-linux-x86_64"
    ;;
  aarch64 | arm64)
    ORT_BINARY="ort-linux-arm64"
    ;;
  *)
    echo "❌ Unsupported Docker architecture: $DOCKER_ARCH"
    exit 1
    ;;
esac

echo "📦 Docker arch: $DOCKER_ARCH → Using ORT binary: $ORT_BINARY"

echo "---"
echo "🐳 Building ORT Docker image..."

docker build -t ort-cli - <<EOF
FROM eclipse-temurin:21-jdk  # Debian-based (fixes glibc issues)
WORKDIR /workspace

RUN apt-get update && apt-get install -y curl bash git && \
    curl -fLo /usr/local/bin/ort https://github.com/oss-review-toolkit/ort/releases/latest/download/$ORT_BINARY && \
    chmod +x /usr/local/bin/ort && \
    file /usr/local/bin/ort

ENTRYPOINT ["ort"]
EOF

echo "✅ ORT Docker image built as 'ort-cli'"

# -----------------------------
# CONFIRM ORT WORKS
# -----------------------------

docker run --rm ort-cli --version || {
  echo "❌ ORT image failed to run"; exit 1;
}

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

# -----------------------------
# DASHBOARD (WebApp viewer)
# -----------------------------

DASHBOARD_DIR="$REPORT_DIR/ort-web-app"
if [ -d "$DASHBOARD_DIR" ]; then
  echo "---"
  echo "📊 Starting ORT Dashboard at http://localhost:8000 ..."
  cd "$DASHBOARD_DIR"
  python3 -m http.server 8000
else
  echo "⚠️ Dashboard directory not found: $DASHBOARD_DIR"
  echo "Check if 'WebApp' format was correctly generated in the ORT report step."
fi
