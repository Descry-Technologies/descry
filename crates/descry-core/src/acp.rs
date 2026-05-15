use serde::{Deserialize, Serialize};

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
    pub trust_level: String,
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
