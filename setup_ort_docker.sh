#!/usr/bin/env bash
set -uo pipefail

#############################################
# Pretty Output (colors, symbols, headers)
#############################################
# Detect if terminal supports colors
if [[ -t 1 ]] && tput colors >/dev/null 2>&1; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"
  MAGENTA="$(tput setaf 5)"
  CYAN="$(tput setaf 6)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

# Log helpers
header()  { printf "\n${CYAN}${BOLD}===== %s =====${RESET}\n" "$*"; }
info()    { printf "${BLUE}🔷 %s${RESET}\n" "$*"; }
success() { printf "${GREEN}✅ %s${RESET}\n" "$*"; }
warn()    { printf "${YELLOW}⚠️  %s${RESET}\n" "$*"; }
error()   { printf "${RED}❌ %s${RESET}\n" "$*"; }

# Error trap for nice failures
trap 'rc=$?; if (( rc != 0 )); then error "Pipeline failed (exit code $rc)"; fi' EXIT

#############################################
# Configuration
#############################################
PROJECT_DIR="${PROJECT_DIR:-$HOME/project}"                     # Local path for the repository
CONFIG_DIR="${CONFIG_DIR:-$HOME/FOSShub/ort-config}"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/project/ort-output-$(date +%Y%m%d-%H%M%S)}"
ORT_IMAGE="${ORT_IMAGE:-ghcr.io/oss-review-toolkit/ort:latest}"
CERT_FILE_HOST_PATH="${CERT_FILE_HOST_PATH:-$HOME/certificate.pem}"
CERT_FILE_DOCKER_PATH="/tmp/certificate.pem"
TRUST_STORE_PASSWORD="${TRUST_STORE_PASSWORD:-changeit}"
BRANCH="${BRANCH:-main}"
export JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"

# Java opts (custom truststore)
JAVA_TOOL_OPTIONS_VALUE="-Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks -Djavax.net.ssl.trustStorePassword=$TRUST_STORE_PASSWORD"

# Performance caches
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"   # persists Trivy vuln DB & cache
ORT_CACHE_DIR="${ORT_CACHE_DIR:-$HOME/.cache/ort}"         # persists ORT cache between runs
KEEP_TRIVY_CDX="${KEEP_TRIVY_CDX:-false}"                  # ORT already outputs CycloneDX; keep Trivy CDX only if needed

# Show config
header "Configuration"
info "Project directory : ${BOLD}$PROJECT_DIR${RESET}"
info "Config directory  : ${BOLD}$CONFIG_DIR${RESET}"
info "Output directory  : ${BOLD}$OUTPUT_DIR${RESET}"
info "ORT image         : ${BOLD}$ORT_IMAGE${RESET}"
info "Custom CA file    : ${BOLD}$CERT_FILE_HOST_PATH${RESET}"
info "Trivy cache       : ${BOLD}$TRIVY_CACHE_DIR${RESET}"
info "ORT cache         : ${BOLD}$ORT_CACHE_DIR${RESET}"
info "Keep Trivy CDX    : ${BOLD}$KEEP_TRIVY_CDX${RESET}"

#############################################
# Pre-flight checks
#############################################
header "Pre-flight Checks"

# Certificate present?
if [[ ! -f "$CERT_FILE_HOST_PATH" ]]; then
  error "Certificate file not found at $CERT_FILE_HOST_PATH"
  exit 1
fi
success "Certificate file found"

# .ort.yml present?
if [[ ! -f "$PROJECT_DIR/.ort.yml" ]]; then
  error "No .ort.yml found in $PROJECT_DIR. This file is required for VCS info."
  exit 1
fi
success ".ort.yml present"

# Create directories
mkdir -p "$OUTPUT_DIR"/{analyzer-result,scanner-result,advisor-result,evaluator-result,report-result,syft-result,trivy-result}
mkdir -p "$TRIVY_CACHE_DIR" "$ORT_CACHE_DIR"
success "Output and cache directories ready"

#############################################
# ORT Analyze
#############################################
header "ORT Analyze"
info "Starting analyzer (with custom truststore)..."
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -v "$CERT_FILE_HOST_PATH":"$CERT_FILE_DOCKER_PATH" \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$ORT_CACHE_DIR":/home/ort/.cache \
  -e "JAVA_HOME=$JAVA_HOME" \
  --entrypoint /bin/sh \
  "$ORT_IMAGE" -c "
    cp \"\$JAVA_HOME/lib/security/cacerts\" /ort/data/custom-cacerts.jks && \
    keytool -import -trustcacerts -keystore /ort/data/custom-cacerts.jks \
      -storepass \"$TRUST_STORE_PASSWORD\" -alias example_cert \
      -file \"$CERT_FILE_DOCKER_PATH\" -noprompt && \
    export JAVA_TOOL_OPTIONS=\"-Djavax.net.ssl.trustStore=/ort/data/custom-cacerts.jks \
    -Djavax.net.ssl.trustStorePassword=$TRUST_STORE_PASSWORD\" && \
    ort analyze \
      -i /project \
      -o /ort/data/analyzer-result \
      --repository-configuration-file /project/.ort.yml
  "

ANALYZE_RESULT="$(find "$OUTPUT_DIR/analyzer-result" -type f -name "analyzer-result*.yml" | sort | tail -n 1 || true)"
if [[ -s "${ANALYZE_RESULT:-}" ]]; then
  success "Analyzer result: ${BOLD}$ANALYZE_RESULT${RESET}"
else
  error "Analyzer result missing or empty."
  exit 1
fi

#############################################
# ORT Scan
#############################################
header "ORT Scan"
info "Running ORT scan (ScanCode; using persisted ORT cache)..."
docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -v "$ORT_CACHE_DIR":/home/ort/.cache \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  --package-types "PROJECT,PACKAGE" \
  --skip-excluded \
  -o /ort/data/scanner-result

SCAN_RESULT="$(find "$OUTPUT_DIR/scanner-result" -type f -name "scan-result*.yml" | sort | tail -n 1 || true)"
if [[ -s "${SCAN_RESULT:-}" ]]; then
  success "Scan result: ${BOLD}$SCAN_RESULT${RESET}"
else
  error "Scan result missing or empty."
  exit 1
fi

#############################################
# Syft & Trivy — run in parallel
#############################################
header "SBOM Generation (Syft & Trivy in Parallel)"

SYFT_OUTPUT_DIR="$OUTPUT_DIR/syft-result"
TRIVY_OUTPUT_DIR="$OUTPUT_DIR/trivy-result"

info "Launching Syft SPDX..."
(
  docker run --rm \
    -e SYFT_CHECK_FOR_UPDATES=false \
    -v "$PROJECT_DIR":/project:ro \
    -v "$SYFT_OUTPUT_DIR":/output \
    -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem \
    -e SSL_CERT_FILE=/tmp/certificate.pem \
    ghcr.io/anchore/syft:latest \
    /project -o spdx-json=/output/sbom-spdx.json
) &

info "Launching Syft CycloneDX..."
(
  docker run --rm \
    -e SYFT_CHECK_FOR_UPDATES=false \
    -v "$PROJECT_DIR":/project:ro \
    -v "$SYFT_OUTPUT_DIR":/output \
    -v "$CERT_FILE_HOST_PATH":/tmp/certificate.pem \
    -e SSL_CERT_FILE=/tmp/certificate.pem \
    ghcr.io/anchore/syft:latest \
    /project -o cyclonedx-json=/output/sbom-cdx.json
) &

info "Launching Trivy SPDX with persistent cache..."
(
  docker run --rm \
    -v "$PROJECT_DIR":/project:ro \
    -v "$TRIVY_OUTPUT_DIR":/trivy \
    -v "$TRIVY_CACHE_DIR":/root/.cache/trivy \
    aquasec/trivy:latest fs /project \
    --format spdx-json \
    > "$TRIVY_OUTPUT_DIR/trivy-spdx.json"
) &

if [[ "$KEEP_TRIVY_CDX" == "true" ]]; then
  info "Launching Trivy CycloneDX with persistent cache..."
  (
    docker run --rm \
      -v "$PROJECT_DIR":/project:ro \
      -v "$TRIVY_OUTPUT_DIR":/trivy \
      -v "$TRIVY_CACHE_DIR":/root/.cache/trivy \
      aquasec/trivy:latest fs /project \
      --format cyclonedx \
      > "$TRIVY_OUTPUT_DIR/trivy-cdx.json"
  ) &
fi

# Wait for background jobs
wait

SYFT_SPX="$SYFT_OUTPUT_DIR/sbom-spdx.json"
SYFT_CDX="$SYFT_OUTPUT_DIR/sbom-cdx.json"
TRIVY_SPDX="$TRIVY_OUTPUT_DIR/trivy-spdx.json"
TRIVY_CDX="$TRIVY_OUTPUT_DIR/trivy-cdx.json"

[[ -s "$SYFT_SPX"  ]] && success "Syft SPDX SBOM: ${BOLD}$SYFT_SPX${RESET}"   || warn "Syft SPDX SBOM missing or empty."
[[ -s "$SYFT_CDX"  ]] && success "Syft CycloneDX SBOM: ${BOLD}$SYFT_CDX${RESET}" || warn "Syft CycloneDX SBOM missing or empty."
[[ -s "$TRIVY_SPDX" ]] && success "Trivy SPDX SBOM: ${BOLD}$TRIVY_SPDX${RESET}"  || warn "Trivy SPDX SBOM missing or empty."
if [[ "$KEEP_TRIVY_CDX" == "true" ]]; then
  [[ -s "$TRIVY_CDX" ]] && success "Trivy CycloneDX SBOM: ${BOLD}$TRIVY_CDX${RESET}" || warn "Trivy CycloneDX SBOM missing or empty."
fi

#############################################
# ORT Advise
#############################################
header "ORT Advise"
info "Advisors: OSV, OSSIndex, VulnerableCode"
docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" advise \
  --advisors="OSV,OSSIndex,VulnerableCode" \
  --ort-file "/ort/data/scanner-result/$(basename "$SCAN_RESULT")" \
  -o /ort/data/advisor-result

ADVISE_RESULT="$(find "$OUTPUT_DIR/advisor-result" -type f -name "advisor-result*.yml" | sort | tail -n 1 || true)"
if [[ -s "${ADVISE_RESULT:-}" ]]; then
  success "Advisor result: ${BOLD}$ADVISE_RESULT${RESET}"
else
  error "Advisor result missing or empty."
  exit 1
fi

#############################################
# ORT Evaluate
#############################################
header "ORT Evaluate"
info "Applying policy rules.kts"
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" evaluate \
  --ort-file /ort/data/advisor-result/advisor-result.yml \
  -r /home/ort/.ort/config/rules.kts \
  -o /ort/data/evaluator-result

EVAL_RESULT="$(find "$OUTPUT_DIR/evaluator-result" -type f -name "evaluation-result*.yml" | sort | tail -n 1 || true)"
if [[ -s "${EVAL_RESULT:-}" ]]; then
  success "Evaluator result: ${BOLD}$EVAL_RESULT${RESET}"
else
  error "Evaluator result missing or empty."
  exit 1
fi

#############################################
# ORT Report
#############################################
header "ORT Report"
info "Generating reports: CycloneDX, HtmlTemplate, WebApp, PdfTemplate"
docker run --rm \
  -v "$PROJECT_DIR":/project:ro \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" report \
  --ort-file /ort/data/evaluator-result/"$(basename "$EVAL_RESULT")" \
  -o /ort/data/report-result \
  --report-formats "SpdxDocument,CycloneDX,HtmlTemplate,WebApp,PdfTemplate"

REPORT_RESULT="$(find "$OUTPUT_DIR/report-result" -type f \( -name "*.html" -o -name "*.json" \) | sort | tail -n 1 || true)"
if [[ -s "${REPORT_RESULT:-}" ]]; then
  success "Report generated: ${BOLD}$REPORT_RESULT${RESET}"
else
  error "Report generation failed or empty."
  exit 1
fi

#############################################
# Summary
#############################################
header "Summary"
printf "${GREEN}${BOLD}🎉 ORT pipeline completed successfully!${RESET}\n"
printf "${MAGENTA}${BOLD}Results:${RESET}\n"
printf "  Analyzer   : %s\n" "${ANALYZE_RESULT:-<missing>}"
printf "  Scanner    : %s\n" "${SCAN_RESULT:-<missing>}"
printf "  Advisor    : %s\n" "${ADVISE_RESULT:-<missing>}"
printf "  Evaluator  : %s\n" "${EVAL_RESULT:-<missing>}"
printf "  Reporter   : %s\n" "${REPORT_RESULT:-<missing>}"
printf "  Syft SPDX  : %s\n" "${SYFT_SPX:-<missing>}"
printf "  Syft CDX   : %s\n" "${SYFT_CDX:-<missing>}"
printf "  Trivy SPDX : %s\n" "${TRIVY_SPDX:-<missing>}"
if [[ "$KEEP_TRIVY_CDX" == "true" ]]; then
  printf "  Trivy CDX  : %s\n" "${TRIVY_CDX:-<missing>}"
fi

# Clear error trap on success
trap - EXIT
exit 0
