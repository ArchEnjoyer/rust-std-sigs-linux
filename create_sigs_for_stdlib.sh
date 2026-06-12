#!/bin/bash

versions=(
    "1.96.0"
    "1.95.0"
    "1.94.1"
    "1.94.0"
    "1.93.1"
    "1.93.0"
    "1.92.0"
    "1.91.1"
    "1.91.0"
    "1.90.0"
    "1.89.0"
    "1.88.0"
    "1.87.0"
    "1.86.0"
    "1.85.1"
    "1.84.1"
    "1.84.0"
    "1.83.0"
    "1.82.0"
    "1.81.0"
    "1.80.1"
    "1.80.0"
)

for ver in "${versions[@]}"; do
    echo "=== Processing Rust version: $ver ==="
    target_dir="$ver"
    mkdir -p "$target_dir"
    cd "$target_dir" || { echo "ERROR: Cannot cd into $target_dir"; continue; }

    if rustbinsign -l DEBUG sign_stdlib \
        --provider IDA \
        --toolchain "${ver}-x86_64-unknown-linux-gnu"
    then
        echo "SUCCESS: $ver"
    else
        echo "ERROR: Command failed for $ver" >&2
    fi

    cd - > /dev/null || exit 1
    echo "=== Finished $ver ==="
done

echo "All done (some versions may have failed)."
