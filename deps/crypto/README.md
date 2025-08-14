# C2L

Core cryptography library for the Tusk mobile voting project.

## Overview

Contains the primitives necessary to implement the Tusk mobile voting end-to-end verifiable e-voting protocol.

## ⚠️ Requirements

This crate requires the **nightly** Rust compiler. To install and use the nightly toolchain, run:
```bash
rustup default nightly
```

## Building Documentation

**1. Generate the Documentation**

Run the following Cargo command from the root of the project:

```bash
cargo doc --no-deps
```

**2. Open in Your Browser**

Once the command finishes, the main documentation page will be located at:

```code
target/doc/crypto/index.html
```

Open this file in your web browser to view the docs.

You can also run this command, which will automatically build the docs and open the main page in your default browser:

```bash
cargo doc --no-deps --open
```

## Usage

For example, to generate a keypair, encrypt an elgamal ciphertext of width 3, and decrypt it:

```rust,ignore
use std::array;

use crate::context::Context;
use crate::context::RistrettoCtx as Ctx;
use crate::cryptosystem::elgamal::{KeyPair, Ciphertext};

const W: usize = 3;
let keypair = KeyPair::<Ctx>::generate();
let message = array::from_fn(|_| Ctx::random_element());

let ciphertext: Ciphertext<Ctx, W> = keypair.encrypt(&message);
let decrypted_message = keypair.decrypt(&ciphertext);
assert_eq!(message, decrypted_message);
```

### Running Tests

To run tests, use the following command:

```bash
cargo test
```