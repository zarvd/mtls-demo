#!/usr/bin/env bash

CUR_DIR=$(dirname "$0")

set -euo pipefail

for i in {1..1000}; do
    SEQ=$(printf "%04d" $i)
    OUTPUT_FILE="$CUR_DIR/self-signed-root-ca-$SEQ.yaml"
    if [[ ! -f "$OUTPUT_FILE" ]]; then
        cp "$CUR_DIR/templates/self-signed-root-ca.yaml.tpl" "$OUTPUT_FILE"
        sed -i '' "s/0001/$SEQ/g" "$OUTPUT_FILE"  # A very simple way to generate a unique issuer name

        echo "Generated $OUTPUT_FILE"
        break
    fi
done
