#![allow(dead_code)]


pub mod util;
pub mod hashing;
pub mod signature;
pub mod bb;
pub mod protocol;
pub mod artifact;
pub mod statement;
pub mod localstore;
pub mod action;
pub mod memory_bb;
pub mod trustee;

pub use crypto::context::Context;

trait Application {
    type Context: Context;
    const W: usize;
    const T: usize;
    const P: usize;
}