#!/usr/bin/env bash
set -euo pipefail

rustup toolchain install 1.86.0 > /dev/null 2>&1 || true

packages=(
    "aes 0.8.4 0.9.0-pre"
    "chrono 0.4.40"
    "cipher 0.5.0-pre.8 0.5.0-rc.0"
    "clap 4.5.34 4.5.36"
    "crossterm 0.28.1 0.29.0"
    "der 0.7.10 0.8.0-rc.1"
    "generic-array 0.2.0"
    "gimli 0.31.1"
    "hashbrown 0.15.2"
    "indexmap 2.8.0 2.9.0"
    "memchr 2.7.4"
    "miniz_oxide 0.8.5 0.8.7"
    "num-bigint-dig 0.7.1"
    "once_cell 1.21.3"
    "path-absolutize 3.1.1"
    "pkcs1 0.8.0-rc.1"
    "pkcs8 0.11.0-rc.2"
    "priority-queue 2.3.1"
    "rand 0.9.0 0.9.1"
    "rand_core 0.9.2 0.9.3"
    "rsa 0.9.8 0.10.0-pre.4"
    "serde 1.0.218 1.0.219"
    "serde_json 1.0.139 1.0.140"
    "smallvec 1.15.0 2.0.0-alpha.11"
    "spin 0.9.8 0.10.0"
    "tui 0.18.0 0.19.0"
    "zeroize 1.8.1"
    "rayon 1.10.0"
)

for entry in "${packages[@]}"; do
    read -ra tokens <<< "$entry"
    crate="${tokens[0]}"
    versions=("${tokens[@]:1}")

    for ver in "${versions[@]}"; do
        dir="${crate}-${ver}"
        mkdir -p "$dir"
        echo ">>> Создаю сигнатуру для ${crate} v${ver} в папке $dir"
        (
            cd "$dir"
            rustbinsign -l DEBUG download_sign \
                --provider IDA \
                "${crate}-${ver}" \
                1.86.0-x86_64-unknown-linux-gnu || echo "ОШИБКА: не удалось создать сигнатуру для ${crate}-${ver}"
        )
        echo "----------------------------------------"
    done
done

echo "Готово."
