use std::fmt;

use serde::de::{Error as DeError, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Validated enumeration of agent trust levels.
///
/// Unknown values deserialize to `TrustLevel::Unknown` rather than failing,
/// preserving forward compatibility while guaranteeing the set of recognized
/// levels is closed and auditable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustLevel {
    LocalDevAgent,
    CiAgent,
    RemoteAgent,
    Unknown,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDevAgent => "local_dev_agent",
            Self::CiAgent => "ci_agent",
            Self::RemoteAgent => "remote_agent",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for TrustLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TrustLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TrustLevelVisitor;

        impl Visitor<'_> for TrustLevelVisitor {
            type Value = TrustLevel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a trust level string: local_dev_agent, ci_agent, remote_agent, or unknown",
                )
            }

            fn visit_str<E: DeError>(self, value: &str) -> Result<TrustLevel, E> {
                Ok(match value {
                    "local_dev_agent" => TrustLevel::LocalDevAgent,
                    "ci_agent" => TrustLevel::CiAgent,
                    "remote_agent" => TrustLevel::RemoteAgent,
                    _ => {
                        // Warn callers about unrecognized values by emitting "unknown"
                        // rather than hard-erroring, preserving forward compatibility.
                        let _ = Unexpected::Str(value);
                        TrustLevel::Unknown
                    }
                })
            }
        }

        deserializer.deserialize_str(TrustLevelVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionProvenance {
    User,
    AgentReasoning,
    ToolOutput,
    RepoContent,
    WebContent,
}

impl InstructionProvenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::AgentReasoning => "agent reasoning",
            Self::ToolOutput => "external tool output",
            Self::RepoContent => "repository content",
            Self::WebContent => "web content",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Source {
    #[serde(rename = "type")]
    pub source_type: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Actor {
    #[serde(rename = "type")]
    pub actor_type: String,
    pub name: String,
    pub owner: String,
    pub trust_level: TrustLevel,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String,
    pub verb: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    pub diff_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Intent {
    pub active_task: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_prompt: Option<String>,
    pub source: String,
    pub linked_issue: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Asset {
    #[serde(rename = "type")]
    pub asset_type: String,
    pub sensitivity: String,
    pub environment: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Context {
    pub repo: String,
    pub branch: String,
    pub recent_files: Vec<String>,
    pub recent_approvals: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BlastRadius {
    pub reversible: bool,
    pub customer_impact: String,
    pub financial_impact: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ActionContextPacket {
    pub actor: Actor,
    pub action: Action,
    pub intent: Intent,
    pub asset: Asset,
    pub context: Context,
    pub blast_radius: BlastRadius,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_provenance: Option<InstructionProvenance>,
}
