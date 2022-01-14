# TENET
A godawful jwt implementation

![Crates.io](https://img.shields.io/crates/v/tenet?style=for-the-badge)
![docs.rs](https://img.shields.io/docsrs/tenet?style=for-the-badge)
![Crates.io](https://img.shields.io/crates/d/tenet?style=for-the-badge)
![Crates.io](https://img.shields.io/crates/l/tenet?style=for-the-badge)

```toml
[dependencies.jwt]
package="tenet"
version = "*"
features = ["HS256"]
```
### Don't use this
This library is slow, baldly implemented and took a total of 20 minutes to write and bug check.

You are much better off using another tried and tested JWT implementation:
- [`frank_jwt`](https://crates.io/crates/frank_jwt)
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken)
- [`biscuit`](https://crates.io/crates/biscuit)
- [`jsonwebtokens`](https://crates.io/crates/jsonwebtokens)


**Why does it exist?**
I got fed up with shitty API design around signing and verifying tokens.

- This library has only two separate token types.
- This library does not do any verification on a token payload.

### Types

This library has two token types:
- A unsigned token with a given type (`Token<T>`)
- A signed token (`SignedToken`)

Token algorithms are decided by a enum: `TokenAlgorithm`

### Supported Algorithms
- `HS256`
- `HS512`
### Example

```rust
use serde::{Serialize, Deserialize};
use jwt::{Token, TokenAlgorithm, SignedToken};

// Create a new token type.
// This uses serde's Serialize and Deserialize procedural macros.
#[derive(Serialize, Deserialize, Debug)]
struct MyToken {
    foo: u8,
    bar: bool,
    baz: String,
}

// create a key to sign and verify tokens.
let token_key = b"VERY_SECURE_KEY".to_vec();

// create a new token, sign it, and get the string representation
let token = Token::create(
    TokenAlgorithm::HS256,
    MyToken { foo: 10, bar: true, baz: "Hello World".to_string() }
)
.sign(&token_key).unwrap().string();

println!("{}", token);

// verify a token input
let payload = Token::<MyToken>::verify(token, &token_key).unwrap();

println!("{:?}", payload);
```
