#![allow(dead_code)]
#![feature(generic_const_items)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]


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

use serde::{de::DeserializeOwned, Serialize};
pub use crypto::context::Context;

pub trait Application: Clone + Serialize + DeserializeOwned + PartialEq + Send + Sync + 'static {
    type Context: Context + Serialize + DeserializeOwned;
    const W: usize;
    const T: usize;
    const P: usize;
}

