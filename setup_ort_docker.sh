#!/bin/bash
set -e

# --- CONFIG ---
PROJECT_DIR="./project"
REPORT_DIR="./reports"
ORT_DIR="./ort-results"
SCANCODE_DIR="$HOME/scancode-toolkit"

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

# --- Download ScanCode Toolkit if not present ---
if [ ! -d "$SCANCODE_DIR" ]; then
  echo "🔍 Downloading ScanCode Toolkit..."
  wget -q https://github.com/nexB/scancode-toolkit/releases/download/v32.1.1/scancode-toolkit-32.1.1.zip -O scancode.zip
  unzip -q scancode.zip
  mv scancode-toolkit-32.1.1 "$SCANCODE_DIR"
  rm scancode.zip
fi

# --- Check for ScanCode virtualenv ---
if [ ! -f "$SCANCODE_DIR/venv/bin/scancode" ]; then
  echo ""
  echo "❌ ScanCode virtualenv not initialized!"
  echo "➡️  Please run the following manually before retrying:"
  echo ""
  echo "   cd ~/scancode-toolkit"
  echo "   python3 -m venv venv"
  echo "   source venv/bin/activate"
  echo "   pip install -r requirements.txt"
  echo "   ./scancode --version"
  echo "   deactivate"
  echo ""
  exit 1
fi

export PATH="$PATH:$(pwd)/bin:$SCANCODE_DIR"

# --- Verify Tools ---
echo "✅ Tool Versions:"
./bin/syft version
./bin/trivy version
"$SCANCODE_DIR/scancode" --version
ort --version || { echo "❌ ORT CLI not found. Please install it."; exit 1; }

# --- Run Scans ---
echo "📦 Generating SBOM with Syft..."
./bin/syft dir:$PROJECT_DIR -o spdx-json > "$REPORT_DIR/sbom.spdx.json"

echo "🛡️ Running Trivy scan..."
./bin/trivy fs $PROJECT_DIR --format json --output "$REPORT_DIR/trivy-report.json"

echo "🔍 Running ScanCode Toolkit..."
"$SCANCODE_DIR/scancode" --license --copyright --info \
  --json-pp "$REPORT_DIR/scancode-report.json" "$PROJECT_DIR"

echo "🔬 Running ORT pipeline..."
ort analyze -i "$PROJECT_DIR" -o "$ORT_DIR/analyzer"
ort scan -i "$ORT_DIR/analyzer/analyzer-result.yml" -o "$ORT_DIR/scanner"
ort evaluate -i "$ORT_DIR/scanner" -o "$ORT_DIR/evaluator"
ort report -i "$ORT_DIR/evaluator" -o "$ORT_DIR/report" -f WebApp,SpdxDocument,CycloneDx,StaticHtml

echo "🌐 Launching Web UI at http://localhost:3000 ..."
docker-compose up --build
