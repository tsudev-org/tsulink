//! Cầu Rust ↔ Dart của Tsu Link (flutter_rust_bridge, ADR-0005).
//!
//! Chỉ `api` là bề mặt cho Dart (codegen quét module này). `frb_generated` do `scripts/gen-dart-bridge.sh` sinh -
//! KHÔNG sửa tay; CI sinh lại và so `git diff`.

pub mod api;
#[allow(
    missing_docs,
    unsafe_code,
    clippy::all,
    unused_qualifications,
    unexpected_cfgs,
    non_camel_case_types,
    unused
)]
mod frb_generated;
