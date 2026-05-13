use serde::{Deserialize, Serialize};

use crate::{Confidence, RiskScore};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    AllowWithLog,
    Ask,
    RequireApproval,
    Block,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DecisionOutput {
    pub decision: Decision,
    pub risk_score: RiskScore,
    pub confidence: Confidence,
    pub reason: String,
    pub conditions: Vec<String>,
}
