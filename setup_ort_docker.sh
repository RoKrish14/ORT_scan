#!/bin/bash
set -e

# --- CONFIG ---
PROJECT_DIR="./project"
REPORT_DIR="./reports"
ORT_DIR="./ort-results"

# --- CHECK INPUT ---
if [ ! -d "$PROJECT_DIR" ]; then
  echo "❌ ERROR: Project directory '$PROJECT_DIR' not found."
  echo "➡️  Please place your codebase to scan inside './project'"
  exit 1
fi

mkdir -p "$REPORT_DIR" "$ORT_DIR" "./bin"

# --- Install Syft ---
if [ ! -f ./bin/syft ]; then
  echo "📦 Installing Syft..."
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin
fi

# --- Install Trivy ---
if [ ! -f ./bin/trivy ]; then
  echo "🛡️ Installing Trivy..."
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ./bin
fi

export PATH="$PATH:$(pwd)/bin"

# --- Verify Tools ---
echo "✅ Tool Versions:"
./bin/syft version
./bin/trivy version
ort --version || { echo "❌ ORT CLI not found. Please install it."; exit 1; }

# --- Run Syft (SBOM) ---
echo "📦 Generating SBOM with Syft..."
./bin/syft dir:$PROJECT_DIR -o spdx-json > "$REPORT_DIR/sbom.spdx.json"

# --- Run Trivy (Vulnerability Scan) ---
echo "🛡️ Running Trivy scan..."
./bin/trivy fs $PROJECT_DIR --format json --output "$REPORT_DIR/trivy-report.json"

# --- Run ORT ---
echo "🔬 Running ORT pipeline..."
ort analyze -i "$PROJECT_DIR" -o "$ORT_DIR/analyzer"
ort scan -i "$ORT_DIR/analyzer/analyzer-result.yml" -o "$ORT_DIR/scanner"
ort evaluate -i "$ORT_DIR/scanner" -o "$ORT_DIR/evaluator"
ort report -i "$ORT_DIR/evaluator" -o "$ORT_DIR/report" -f WebApp,SpdxDocument,CycloneDx,StaticHtml

# --- Launch Dashboard ---
echo "🌐 Launching Web UI at http://localhost:3000 ..."
docker-compose up --build
