use serde::Deserialize;

use crate::matcher::CompiledHardBlock;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HardBlock {
    pub id: String,
    pub action: String,
    #[serde(default)]
    pub command_matches: Vec<String>,
    #[serde(default)]
    pub command_regex: Option<String>,
    #[serde(default)]
    pub target_matches: Vec<String>,
    #[serde(default)]
    pub target_regex: Option<String>,
    #[serde(default)]
    pub summary_matches: Vec<String>,
    #[serde(default)]
    pub summary_regex: Option<String>,
    #[serde(default)]
    pub argument_key_matches: Vec<String>,
    #[serde(default)]
    pub argument_key_regex: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub project: Project,
    pub hard_blocks: Vec<HardBlock>,
    #[serde(skip)]
    pub(crate) compiled_hard_blocks: Vec<CompiledHardBlock>,
}
