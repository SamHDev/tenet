//! # JWT Watchflow
//! A godawful jwt implementation
//!
//! ```toml
//! [dependencies.jwt]
//! package="jwt_watchflow"
//! version = "*"
//! features = ["HS256"]
//! ```
//! ### Don't use this
//! This library is slow, baldly implemented and took a total of 20 minutes to write and bug check.
//!
//! You are much better off using another tried and tested JWT implementation:
//! - [`frank_jwt`](https://crates.io/crates/frank_jwt)
//! - [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken)
//! - [`biscuit`](https://crates.io/crates/biscuit)
//! - [`jsonwebtokens`](https://crates.io/crates/jsonwebtokens)
//!
//!
//! **Why does it exist?**
//! I got fed up with shitty API design around signing and verifying tokens.
//!
//! - This library has only two separate token types.
//! - This library does not do any verification on a token payload.
//!
//! ### Types
//!
//! This library has two token types:
//! - A unsigned token with a given type (`Token<T>`)
//! - A signed token (`SignedToken`)
//!
//! Token algorithms are decided by a enum: `TokenAlgorithm`
//!
//! ### Supported Algorithms
//! - `HS256`
//! - `HS512`

//! ### Example
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use jwt_watchflow::{Token, TokenAlgorithm, SignedToken};
//!
//! // Create a new token type.
//! // This uses serde's Serialize and Deserialize procedural macros.
//! #[derive(Serialize, Deserialize, Debug)]
//! struct MyToken {
//!     foo: u8,
//!     bar: bool,
//!     baz: String
//! }
//!
//! // create a key to sign and verify tokens.
//! let token_key = b"VERY_SECURE_KEY";
//!
//! // create a new token, sign it, and get the string representation
//! let token = Token::create(
//!     TokenAlgorithm::HS256,
//!     MyToken { foo: 10, bar: true, baz: "Hello World".to_string() }
//! )
//! .sign(&token_key).unwrap().string();
//!
//! println!("{}", token);
//!
//! // verify a token input
//! let payload = Token::<MyToken>::verify(token, &token_key).unwrap();
//!
//! println!("{:?}", payload);
//! ```


use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

#[cfg(feature="hmac")]
use hmac::Mac;

const DOT: u8 = '.' as u8;
static TYPE: &'static str = "JWT";

/// JWT Token Header
#[derive(Serialize, Deserialize)]
pub struct TokenHeader {
    #[serde(skip_serializing_if="Option::is_none")]
    #[serde(rename="type")]
    pub _type: Option<String>,

    #[serde(rename="alg")]
    pub algorithm: TokenAlgorithm,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
/// Token Signing and Verifying Algorithm
pub enum TokenAlgorithm {
    #[cfg(feature="HS256")]
    HS256,
    #[cfg(feature="HS512")]
    HS512,
    #[serde(other)]
    Other
}

/// Unsigned JWT Token
///
/// Stores payload object and header.
pub struct Token<T> {
    pub header: TokenHeader,
    pub payload: T
}

#[derive(Clone)]
/// Signed JWT Token
///
/// Stores:
/// - algorithm
/// - body (encoding header & payload)
/// - signature
pub struct SignedToken {
    algorithm: TokenAlgorithm,
    body: Vec<u8>,
    signature: Vec<u8>
}

#[derive(Debug)]
/// JWT Error
pub enum TokenError {
    /// algorithm is not recognised or unsupported
    UnsupportedAlgorithm,
    /// invalid signing/verify key when creating algorithm
    InvalidKey,
    /// invalid header while parsing/decoding
    InvalidHeader,
    /// payload failed to serialise or deserialise
    InvalidPayload(serde_json::Error),

    /// token was invalid
    InvalidToken,
    /// signature was invalid
    InvalidSignature
}

fn b64_encode<S: AsRef<[u8]>>(input: S) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.resize(input.as_ref().len() * 4 / 3 + 4, 0);
    let decode = base64::encode_config_slice(
        input.as_ref(),
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
        &mut buffer
    );
    buffer.truncate(decode);
    buffer
}


fn b64_decode<S: AsRef<[u8]>>(input: S) -> Result<Vec<u8>, TokenError> {
    let input = input.as_ref();
    let mut buffer = vec![0; (input.len() + 3) / 4 * 3];
    let decode = base64::decode_config_slice(
        input,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
        &mut buffer
    );

    match decode {
        Err(_) => Err(TokenError::InvalidToken),
        Ok(size) => {
            buffer.truncate(size);
            Ok(buffer)
        }
    }
}

impl TokenAlgorithm {
    fn name(&self) -> &'static str {
        match &self {
            #[cfg(feature="HS256")]
            TokenAlgorithm::HS256 => "HS256",
            TokenAlgorithm::Other => "Unsupported",
        }
    }

    /// sign a given payload with a key
    pub fn sign<P: AsRef<[u8]>>(&self, payload: P, key: &[u8]) -> Result<Vec<u8>, TokenError> {
        match &self {
            #[cfg(feature="HS256")]
            TokenAlgorithm::HS256 => {
                let mut hash = match hmac::Hmac::<sha2::Sha256>::new_from_slice(&key) {
                    Ok(x) => x,
                    Err(_) => return Err(TokenError::InvalidKey)
                };
                hash.update(payload.as_ref());
                return Ok(hash.finalize().into_bytes().as_slice().to_vec())
            }

            TokenAlgorithm::Other => Err(TokenError::UnsupportedAlgorithm)
        }
    }

    /// verify a given payload and signature with a key
    pub fn verify<P: AsRef<[u8]>>(&self, payload: P, sig: &[u8], key: &[u8]) -> Result<bool, TokenError> {
        match &self {
            #[cfg(feature="HS256")]
            TokenAlgorithm::HS256 => {
                let mut hash = match hmac::Hmac::<sha2::Sha256>::new_from_slice(&key) {
                    Ok(x) => x,
                    Err(_) => return Err(TokenError::InvalidKey)
                };
                hash.update(payload.as_ref());
                Ok(hash.verify_slice(sig).is_ok())
            }

            TokenAlgorithm::Other => Err(TokenError::UnsupportedAlgorithm)
        }
    }
}

impl TokenHeader {
    /// Create a new TokenHeader object
    ///
    /// - `algorithm: TokenAlgorithm` - the signing algorithm to use
    /// - `include_type: bool` - include the `"type": "JWT"` string in the header. (default false)
    pub fn new(algorithm: TokenAlgorithm, include_type: bool) -> Self {
        Self {
            algorithm,
            _type: if include_type { Some(TYPE.to_string()) } else { None }
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, TokenError> {
        match serde_json::to_vec(&self) {
            Ok(x) => Ok(x),
            Err(_) => Err(TokenError::InvalidHeader)
        }
    }

    fn deserialize(input: &[u8]) -> Result<TokenHeader, TokenError> {
        match serde_json::from_slice(input) {
            Ok(x) => Ok(x),
            Err(_) => Err(TokenError::InvalidHeader)
        }
    }
}

impl<T> Token<T> {
    /// Create a new token wiht a given algorithm and payload
    ///
    /// ```
    /// # use jwt_watchflow::{Token, TokenAlgorithm};
    /// # struct Foo { a: u8, b: bool };
    /// let token = Token::create(TokenAlgorithm::HS256, Foo { a: 69, b: false });
    /// ```
    pub fn create(algorithm: TokenAlgorithm, payload: T) -> Self {
        Self {
            header: TokenHeader::new(algorithm, false),
            payload
        }
    }

    /// Create a new token with a token header and payload.
    ///
    /// ```
    /// # use jwt_watchflow::{Token, TokenAlgorithm, TokenHeader};
    /// # struct Foo { a: u8, b: bool };
    /// let token = Token::new(
    ///     TokenHeader::new(TokenAlgorithm::HS256, true),
    ///     Foo { a: 69, b: false }
    /// );
    /// ```
    pub fn new(header: TokenHeader, payload: T) -> Self {
        Self {
            header,
            payload
        }
    }
}

impl<T: Serialize> Token<T>  {
    fn serialize(x: &T) -> Result<Vec<u8>, TokenError> {
        match serde_json::to_vec(x) {
            Ok(x) => Ok(x),
            Err(e) => Err(TokenError::InvalidPayload(e))
        }
    }

    fn build(&self) -> Result<Vec<u8>, TokenError> {
        let mut buffer = b64_encode(&self.header.serialize()?);
        buffer.push(DOT);
        buffer.append(&mut b64_encode(Self::serialize(&self.payload)?));
        Ok(buffer)
    }

    /// Sign a `Token` to a `SignedToken` with a given key
    pub fn sign(&self, key: &[u8]) -> Result<SignedToken, TokenError> {
        let buffer = self.build()?;
        let sign = self.header.algorithm.sign(&buffer, &key)?;

        Ok(SignedToken {
            algorithm: self.header.algorithm.clone(),
            body: buffer ,
            signature: sign
        })
    }
}

impl<T: DeserializeOwned> Token<T> {
    fn deserialize(x: &[u8]) -> Result<T, TokenError> {
        match serde_json::from_slice(x) {
            Ok(x) => Ok(x),
            Err(e) => Err(TokenError::InvalidPayload(e))
        }
    }

    /// decode, verify and deserialise a token input
    pub fn verify<S: AsRef<[u8]>>(input: S, key: &[u8]) -> Result<Self, TokenError>{
        let token = SignedToken::decode(input)?;
        if !token.verify(key)? {
            return Err(TokenError::InvalidSignature)
        }
        token.parse()
    }
}


impl SignedToken {
    /// get the byte representation (by copying bytes) of a signed token
    pub fn bytes(&self) -> Vec<u8> {
        let mut body = self.body.clone();
        body.push(DOT);
        body.append(&mut b64_encode(&self.signature));
        body
    }

    /// convert a signed token (by consuming it) to the byte representation
    pub fn into_bytes(self) -> Vec<u8> {
        let mut body = self.body;
        body.push(DOT);
        body.append(&mut b64_encode(&self.signature));
        body
    }

    /// get the string representation of a signed token
    pub fn string(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).to_string()
    }


    /// Decode a string/bytes into a signed token
    pub fn decode<S: AsRef<[u8]>>(input: S) -> Result<Self, TokenError> {
        let mut parts = input.as_ref().split(|x| x == &DOT).collect::<Vec<&[u8]>>();

        if parts.len() != 3 { return Err(TokenError::InvalidToken) }
        let sig = b64_decode(&parts[2])?;
        let header = TokenHeader::deserialize(&b64_decode(&parts[0])?)?;

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&mut parts[0]);
        buffer.push(DOT);
        buffer.extend_from_slice(&mut parts[1]);

        Ok(SignedToken {
            algorithm: header.algorithm.clone(),
            body: buffer,
            signature: sig
        })
    }

    /// deserialize a signed token into a typed token.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<Token<T>, TokenError> {
        let parts = self.body.split(|x| x == &DOT).collect::<Vec<&[u8]>>();

        let header = TokenHeader::deserialize(&b64_decode(&parts[0])?)?;
        let body = Token::<T>::deserialize(&b64_decode(&parts[1])?)?;

        Ok(Token {
            header,
            payload: body
        })
    }

    /// verify a signed token.
    pub fn verify(&self, key: &[u8]) -> Result<bool, TokenError> {
        self.algorithm.verify(&self.body, &self.signature, key)
    }
}

impl<T: Debug> Debug for Token<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(")?;
        f.write_str(self.header.algorithm.name())?;
        f.write_str(", ")?;
        self.payload.fmt(f)?;
        f.write_str(" )")?;
        Ok(())
    }
}

impl Debug for SignedToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedToken(")?;
        f.write_str(self.algorithm.name())?;
        f.write_str(", ")?;
        for byte in &self.signature {
            f.write_str(&format!("{:x?}", byte))?;
        }
        f.write_str(" )")?;
        Ok(())
    }
}

impl<T> Deref for Token<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> DerefMut for Token<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.payload
    }
}