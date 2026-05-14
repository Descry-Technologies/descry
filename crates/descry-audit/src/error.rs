use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Serde(serde_json::Error),
    MalformedRecord { line: u64, reason: String },
    HashMismatch { seq: u64 },
    SeqGap { expected: u64, found: u64 },
    PrevHashMismatch { seq: u64 },
    BrokenChain { reason: String },
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Serde(error) => write!(formatter, "json error: {error}"),
            Self::MalformedRecord { line, reason } => {
                write!(formatter, "malformed record at line {line}: {reason}")
            }
            Self::HashMismatch { seq } => write!(formatter, "hash mismatch at seq {seq}"),
            Self::SeqGap { expected, found } => {
                write!(
                    formatter,
                    "sequence gap: expected {expected}, found {found}"
                )
            }
            Self::PrevHashMismatch { seq } => {
                write!(formatter, "previous hash mismatch at seq {seq}")
            }
            Self::BrokenChain { reason } => write!(formatter, "broken audit chain: {reason}"),
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serde(error) => Some(error),
            Self::MalformedRecord { .. }
            | Self::HashMismatch { .. }
            | Self::SeqGap { .. }
            | Self::PrevHashMismatch { .. }
            | Self::BrokenChain { .. } => None,
        }
    }
}

impl From<io::Error> for AuditError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serde(error)
    }
}
