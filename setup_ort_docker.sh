docker run --rm \
  -v "$PROJECT_DIR":/project \
  -v "$OUTPUT_DIR":/ort/data \
  -v "$CONFIG_DIR":/home/ort/.ort/config \
  "$ORT_IMAGE" scan \
  --ort-file "/ort/data/analyzer-result/$(basename "$ANALYZE_RESULT")" \
  -o /ort/data/scanner-result
