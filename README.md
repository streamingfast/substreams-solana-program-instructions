# substreams-solana-program-instructions

**Deprecated.** This crate reimplemented Solana program instruction decoding so it could run without the Substreams Rust runtime. Substreams now supports pulling the standard Solana program crates directly, so use those instead of this crate.

## Migrate to the standard crates

Depend on the official crate for the program you decode, for example [`spl-token`](https://crates.io/crates/spl-token) or [`spl-token-2022`](https://crates.io/crates/spl-token-2022):

```toml
[dependencies]
spl-token-2022 = "..."
```

```rust
use spl_token_2022::instruction::TokenInstruction;

let instruction = TokenInstruction::unpack(data)?;
```

## Update your Substreams manifest

The standard Solana program crates pull in `wasm-bindgen` through `getrandom`'s `wasm_js` backend when compiled for `wasm32-unknown-unknown`. Substreams CLI/server v1.16.6 and later resolves those imports through a `wasm-bindgen-shims` runtime extension on the module binary:

```yaml
binaries:
  default:
    type: wasm/rust-v1+wasm-bindgen-shims
    file: ./target/wasm32-unknown-unknown/release/<your_package>.wasm
```

See the [manifest reference](https://docs.substreams.dev/reference-material/substreams-components/manifests) for the `binaries` section, and the [Substreams Solana guide](https://docs.substreams.dev/how-to-guides/develop-your-own-substreams/solana) for decoding patterns.
