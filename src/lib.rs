#![allow(dead_code)]
#![feature(generic_const_exprs)]


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

use serde::Serialize;
pub use crypto::context::Context;

pub trait Application {
    type Context: Context + Serialize;
    const W: usize;
    const T: usize;
    const P: usize;
}