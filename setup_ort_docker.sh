docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  -e JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE" \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  --package-types PROJECT \
  --project-scanners ScanCode \
  --skip-excluded \
  -o /ort/data/scanner-result
