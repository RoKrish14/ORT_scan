#!/bin/bash
set -e

# Define base paths relative to the script's execution directory
# Assuming this script is run from ~/oss-review-fullstack/
PROJECT_DIR="./emoji-java"
REPORT_DIR="./reports"
ORT_DIR="./ort-results"
ORT_GLOBAL_CONFIG_DIR="./ort/.ort/config" # Path to where you've put config.yml
REPOSITORY_CONFIG_FILE="repository.yml"   # Name of your repository.yml file

# --- (Rest of your initial setup, checks, and mkdir commands) ---

# Check if the project directory exists.
if [ ! -d "$PROJECT_DIR" ]; then
  echo "❌ ERROR: Project directory '$PROJECT_DIR' not found."
  echo "Please ensure your project source code is in a folder named 'emoji-java' within the same directory as this script."
  exit 1
fi

export PATH="$PATH:$(pwd)/bin"

echo "---"
echo "✅ Tool Versions:"
# Run Syft and Trivy to check their versions. These pull from Docker Hub.
docker run --rm anchore/syft:latest version
docker run --rm aquasec/trivy:latest version
# Run ORT CLI wrapper to check its version. This uses your local 'ort/cli' image.
./bin/ort --version || { echo "❌ ORT CLI not found or failed to execute."; exit 1; }

echo "---"
echo "📦 Generating SBOM with Syft..."
# Syft generates an SPDX JSON SBOM of your project.
docker run --rm -v "$(pwd)/$PROJECT_DIR":/project -v "$(pwd)/$REPORT_DIR":/output anchore/syft:latest dir:/project -o spdx-json > "$REPORT_DIR/sbom.spdx.json"
echo "SBOM generated at $REPORT_DIR/sbom.spdx.json"

echo "---"
echo "🛡️ Running Trivy scan..."
# Trivy scans your project for vulnerabilities.
docker run --rm -v "$(pwd)/$PROJECT_DIR":/project -v "$(pwd)/$REPORT_DIR":/output aquasec/trivy:latest fs /project --format json --output /output/trivy-report.json
echo "Trivy report generated at $REPORT_DIR/trivy-report.json"

echo "---"
echo "🔬 Running ORT pipeline..."
# ORT Analyze: Detects dependencies.
echo "Running ORT Analyze..."
# ORT commands will now use the paths relative to /workspace inside the container
./bin/ort analyze \
  -i "/workspace/$PROJECT_DIR" \
  -
