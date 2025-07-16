#!/bin/bash
set -e

# -----------------------------
# CONFIGURATION
# -----------------------------

PROJECT_DIR="./emoji-java"
REPORT_DIR="./reports"
ORT_DIR="./ort-results"
ORT_GLOBAL_CONFIG_DIR="./.ort/config"
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
# DETECT DOCKER ARCHITECTURE
# -----------------------------

echo "---"
echo "🧠 Detecting Docker runtime architecture..."
DOCKER_ARCH=$(docker run --rm alpine uname -m)

case "$DOCKER_ARCH" in
  x86_64 | amd64)
    ORT_VERSION="62.2.0"
    ORT_ARCHIVE="ort-${ORT_VERSION}.zip"
    ;;
  aarch64 | arm64)
    echo "⚠️ ARM64 detected. Assuming archive name is same."
    ORT_VERSION="62.2.0"
    ORT_ARCHIVE="ort-${ORT_VERSION}.zip"
    ;;
  *)
    echo "❌ Unsupported Docker architecture: $DOCKER_ARCH"
    exit 1
    ;;
esac

# -----------------------------
# GET LINUX SCANCODE TOOLKIT
# -----------------------------

echo "---"
echo "🔎 Fetching latest ScanCode Toolkit version..."
LATEST_SCANCODE_URL=$(curl -sL https://api.github.com/repos/aboutcode-org/scancode-toolkit/releases/latest \
  | grep "browser_download_url.*scancode-toolkit-.*\.zip" \
  | grep -v "windows" \
  | cut -d '"' -f 4 \
  | head -n 1)

if [ -z "$LATEST_SCANCODE_URL" ]; then
  echo "❌ Failed to get latest ScanCode Toolkit URL."
  exit 1
fi

SCANCODE_ZIP=$(basename "$LATEST_SCANCODE_URL")
SCANCODE_DIR="${SCANCODE_ZIP%.zip}"

echo "📦 Using ScanCode release: $SCANCODE_ZIP"

# -----------------------------
# BUILD ORT IMAGE W/ SCANCODE
# -----------------------------

echo "---"
echo "🐳 Rebuilding ORT Docker image with ScanCode..."
docker rmi ort-cli 2>/dev/null || true

docker build -f - . -t ort-cli --build-arg ORT_VERSION="$ORT_VERSION" --build-arg ORT_ARCHIVE="$ORT_ARCHIVE" --build-arg SCANCODE_URL="$LATEST_SCANCODE_URL" --build-arg SCANCODE_ZIP="$SCANCODE_ZIP" --build-arg SCANCODE_DIR="$SCANCODE_DIR" <<'EOF'
FROM eclipse-temurin:21-jdk
WORKDIR /workspace

ARG ORT_VERSION
ARG ORT_ARCHIVE
ARG SCANCODE_URL
ARG SCANCODE_ZIP
ARG SCANCODE_DIR

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl bash git unzip python3 python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fLo /tmp/${ORT_ARCHIVE} https://github.com/oss-review-toolkit/ort/releases/download/${ORT_VERSION}/${ORT_ARCHIVE} && \
    unzip /tmp/${ORT_ARCHIVE} -d /opt && \
    ln -s /opt/ort-${ORT_VERSION}/bin/ort /usr/local/bin/ort && \
    chmod +x /usr/local/bin/ort && \
    curl -fLo /tmp/${SCANCODE_ZIP} ${SCANCODE_URL} && \
    unzip /tmp/${SCANCODE_ZIP} -d /opt && \
    ln -s /opt/${SCANCODE_DIR}/scancode /usr/local/bin/scancode && \
    chmod +x /usr/local/bin/scancode && \
    rm -rf /tmp/${SCANCODE_ZIP} /tmp/${ORT_ARCHIVE}

ENV PATH="/opt/${SCANCODE_DIR}:${PATH}"

ENTRYPOINT ["ort"]
EOF

echo "✅ ORT Docker image with ScanCode built as 'ort-cli'"

# -----------------------------
# VERIFY ORT
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
# ORT - Full Pipeline
# -----------------------------

echo "---"
echo "🔬 Running ORT pipeline..."
rm -f "$ORT_DIR/"*.json "$ORT_DIR/"*.yml

MOUNT_CONFIG="-v $(pwd)/$ORT_GLOBAL_CONFIG_DIR:/root/.ort/config"

docker run --rm \
  -v "$(pwd):/workspace" \
  $MOUNT_CONFIG \
  -w /workspace \
  ort-cli analyze \
    -i "$PROJECT_DIR" \
    -o "$ORT_DIR" \
    -f JSON \
    --repository-configuration-file "$REPOSITORY_CONFIG_FILE"

docker run --rm \
  -v "$(pwd):/workspace" \
  $MOUNT_CONFIG \
  -w /workspace \
  ort-cli scan \
    -i "$ORT_DIR/analyzer-result.json" \
    -o "$ORT_DIR" \
    --skip-excluded

docker run --rm \
  -v "$(pwd):/workspace" \
  $MOUNT_CONFIG \
  -w /workspace \
  ort-cli evaluate \
    -i "$ORT_DIR/evaluator-input.yml" \
    -o "$ORT_DIR" \
    --rules "/root/.ort/config/rules.kts" \
    --severity-threshold "ERROR"

docker run --rm \
  -v "$(pwd):/workspace" \
  $MOUNT_CONFIG \
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
