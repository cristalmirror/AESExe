#!/usr/bin/env bash
set -euo pipefail
cargo build --release
install -Dm755 target/release/aesexe output/aesexe
echo "AESExe instalado en output/aesexe"
