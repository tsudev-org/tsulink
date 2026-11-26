#!/usr/bin/env bash
# Sinh lại mã cầu Rust ↔ Dart (flutter_rust_bridge) cho bindings/dart (ADR-0005).
# CI chạy script này rồi so `git diff` - mã sinh ra phải luôn khớp bindings/dart/rust/src/api.
set -euo pipefail
cd "$(dirname "$0")/../bindings/dart"
want="2.13.0"
have="$(flutter_rust_bridge_codegen --version | awk '{print $2}')"
if [ "$have" != "$want" ]; then
  echo "Cần flutter_rust_bridge_codegen $want (đang có $have): cargo install flutter_rust_bridge_codegen --version $want --locked" >&2
  exit 1
fi
flutter pub get >/dev/null
flutter_rust_bridge_codegen generate
cd ../.. && cargo fmt --all
