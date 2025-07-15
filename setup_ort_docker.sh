#!/bin/bash
set -e

# Create output directories
mkdir -p reports ort-results

echo "📦 Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin

echo "🛡️ Installing Trivy..."
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ./bin

echo "🔍 Installing ScanCode Toolkit (via pip)..."
pip3 install --user scancode-toolkit

export PATH="$PATH:$(pwd)/bin:$HOME/.local/bin"

# Check versions
echo "✅ Versions:"
syft version
trivy version
scancode --version
ort --version || echo "⚠️ ORT CLI must be installed manually (see README)."

echo "📦 Generating SBOM with Syft..."
syft dir:. -o spdx-json > reports/sbom.spdx.json

echo "🛡️ Scanning with Trivy..."
trivy fs . --format json --output reports/trivy-report.json

echo "🔍 Running ScanCode Toolkit..."
scancode --license --copyright --info --json-pp reports/scancode-report.json .

echo "🔬 Running ORT toolchain..."
ort analyze -i . -o ort-results/analyzer
ort scan -i ort-results/analyzer/analyzer-result.yml -o ort-results/scanner
ort evaluate -i ort-results/scanner -o ort-results/evaluator
ort report -i ort-results/evaluator -o ort-results/report -f WebApp,SpdxDocument,CycloneDx,StaticHtml

echo "✅ All tools completed successfully."
echo "📂 Reports saved in 'reports/' and 'ort-results/'"
echo "🌐 You can now run 'docker-compose up --build' to launch the Web UI at http://localhost:3000"
