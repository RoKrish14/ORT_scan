#!/bin/bash

# setup_ort_docker.sh
# Run the OSS Review Toolkit full toolchain using Docker on Ubuntu 18.04

set -e

# ---- CONFIG ----
PROJECT_DIR="$PWD"
ORT_DIR="$PROJECT_DIR/ort-results"
DOCKER_IMAGE="ghcr.io/oss-review-toolkit/ort"
INPUT_PATH="/project"
OUTPUT_PATH="/project/ort-results"

echo "📦 Pulling ORT Docker image..."
docker pull $DOCKER_IMAGE

echo "📁 Creating output directory: $ORT_DIR"
mkdir -p "$ORT_DIR"

# ---- STEP 1: Analyze ----
echo "🔍 Running ORT Analyzer..."
docker run --rm \
  -v "$PROJECT_DIR":"$INPUT_PATH" \
  $DOCKER_IMAGE \
  analyze -i "$INPUT_PATH" -o "$OUTPUT_PATH/analyzer"

# ---- STEP 2: Scan ----
echo "🧪 Running ORT Scanner..."
docker run --rm \
  -v "$PROJECT_DIR":"$INPUT_PATH" \
  $DOCKER_IMAGE \
  scan -i "$OUTPUT_PATH/analyzer" -o "$OUTPUT_PATH/scanner"

# ---- STEP 3: Evaluate ----
echo "📊 Running ORT Evaluator..."
docker run --rm \
  -v "$PROJECT_DIR":"$INPUT_PATH" \
  $DOCKER_IMAGE \
  evaluate -i "$OUTPUT_PATH/scanner" -o "$OUTPUT_PATH/evaluator"

# ---- STEP 4: Report ----
echo "📝 Generating ORT Report..."
docker run --rm \
  -v "$PROJECT_DIR":"$INPUT_PATH" \
  $DOCKER_IMAGE \
  report -i "$OUTPUT_PATH/evaluator" -o "$OUTPUT_PATH/report"

echo "✅ All steps completed."
echo "📂 Reports saved to: $ORT_DIR/report"
