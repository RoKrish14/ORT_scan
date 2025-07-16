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

echo "---"
echo "🧠 Detecting host architecture..."

# -----------------------------
# DETECT DOCKER ARCHITECTURE & BUILD IMAGE
# -----------------------------

echo "---"
echo "🧠 Detecting Docker runtime architecture..."
# Using alpine here just for uname -m, it's a small image.
DOCKER_ARCH=$(docker run --rm alpine uname -m)

case "$DOCKER_ARCH" in
  x86_64)
    # The ORT binary is inside a zip, and the version is hardcoded for now.
    # We will download the zip and extract the binary.
    ORT_VERSION="62.2.0" # Latest version as of current check
    ORT_ARCHIVE="ort-${ORT_VERSION}.zip"
    ;;
  aarch64 | arm64)
    # ORT might offer arm64 builds, but we need to verify the archive name if this path is taken.
    # For now, focusing on x86_64 as per user's output.
    echo "⚠️ ARM64 detected, but ORT archive name for ARM64 not verified. Using x86_64 logic for now."
    ORT_VERSION="62.2.0" # Latest version as of current check
    ORT_ARCHIVE="ort-${ORT_VERSION}.zip" # Assuming same archive naming convention
    ;;
  *)
    echo "❌ Unsupported Docker architecture: $DOCKER_ARCH"
    exit 1
    ;;
esac

echo "📦 Docker arch: $DOCKER_ARCH → Using ORT version: $ORT_VERSION from archive: $ORT_ARCHIVE"

# Ensure a clean rebuild by removing the existing image
docker rmi ort-cli || true # '|| true' prevents script from exiting if image doesn't exist

# Build ORT image (if not already)
if [ -z "$(docker images -q ort-cli)" ]; then
  echo "---"
  echo "🐳 Building ORT Docker image..."

  docker build -t ort-cli - <<EOF
FROM eclipse-temurin:21-jdk
# Changed from eclipse-temurin:21-jdk-alpine - Moved comment to its own line
WORKDIR /workspace

# Install necessary packages, download, extract, and setup ORT binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl bash git unzip && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fLo /tmp/${ORT_ARCHIVE} https://github.com/oss-review-toolkit/ort/releases/download/${ORT_VERSION}/${ORT_ARCHIVE} && \
    unzip /tmp/${ORT_ARCHIVE} -d /opt && \
    ln -s /opt/ort-${ORT_VERSION}/bin/ort /usr/local/bin/ort && \
    chmod +x /usr/local/bin/ort && \
    rm -rf /tmp/${ORT_ARCHIVE}

ENTRYPOINT ["ort"]
EOF

  echo "✅ ORT Docker image built as 'ort-cli'"
fi

# Show ORT version to validate
docker run --rm -v "$(pwd)":/workspace ort-cli --version || {
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
