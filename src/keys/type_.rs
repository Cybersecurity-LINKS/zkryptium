use serde::Deserialize;
use serde::Serialize;


/// Supported cryptographic key types.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum KeyType {
  /// An `Ed25519` cryptographic key.
  CL03,
  /// An `X25519` cryptographic key.
  BBSplus,
}

impl KeyType {
    /// Returns the [`KeyType`] name as a static `str`.
    pub const fn as_str(&self) -> &'static str {
      match self {
        Self::CL03 => "CL03",
        Self::BBSplus => "BBSplus",
      }
    }
  }