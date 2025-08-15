#![allow(dead_code)]
// Only necessary for custom_warning_macro
#![feature(stmt_expr_attributes)]
// Only necessary for custom_warning_macro
#![feature(proc_macro_hygiene)]
#![doc = include_str!("../README.md")]

// enable these once documentation achieves decency
//
// #![deny(missing_docs)]
// #![deny(rustdoc::missing_crate_level_docs)]
// #![deny(rustdoc::broken_intra_doc_links)]

/// Defines implementation choices for key cryptographic functionalities.
pub mod context;
/// Public key cryptosystems (generic).
pub mod cryptosystem;
/// Distributed key generation and decryption funcionality (generic).
#[crate::warning(
    "Asserts are present in this module. Missing checks for threshold validity (P < T). Not optimized."
)]
pub mod dkgd;
/// Concrete implementations of curve arithmetic.
pub mod groups;
/// Abstractions for curve arithmetic, groups, elements and scalars.
pub mod traits;
/// Utilities such as random number generation, hashing, signatures and serialization.
pub mod utils;
/// Zero-knowldge proofs (generic).
pub mod zkp;

// for wasm benchmark
#[cfg(not(doc))]
pub use zkp::bit::benchmark_prove;

// Custom compiler warnings
pub(crate) use custom_warning_macro::warning;
