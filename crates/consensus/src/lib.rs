//! Requant consensus rules (CHAIN.md): encoding, transactions, blocks, difficulty, emission and an
//! in-memory chain state with reorganisation. The work function is the `tnet` crate (SPEC.md).

pub mod address;
pub mod block;
pub mod chain;
pub mod codec;
pub mod headers;
pub mod params;
pub mod pow;
pub mod tx;
pub mod u256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Malformed or non-canonical bytes.
    Decode(&'static str),
    /// Violates a consensus rule.
    Invalid(&'static str),
    /// The parent block is not known (yet).
    UnknownParent,
    /// Already known.
    Duplicate,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Decode(s) => write!(f, "decode: {s}"),
            Error::Invalid(s) => write!(f, "invalid: {s}"),
            Error::UnknownParent => write!(f, "unknown parent"),
            Error::Duplicate => write!(f, "duplicate"),
        }
    }
}

impl std::error::Error for Error {}
