use std::collections::BTreeMap;
use std::fmt;

use descry_core::AssetMatch;
use globset::{Glob, GlobSet, GlobSetBuilder};
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
    #[serde(default)]
    pub sql_delete_without_where: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_pack_version")]
    pub pack_version: String,
    pub project: Project,
    pub hard_blocks: Vec<HardBlock>,
    #[serde(skip)]
    pub(crate) compiled_hard_blocks: Vec<CompiledHardBlock>,
}

#[derive(Debug)]
pub enum ProjectPolicyError {
    InvalidYaml(serde_yml::Error),
    InvalidGlob {
        rule_id: String,
        source: globset::Error,
    },
}

impl fmt::Display for ProjectPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(formatter, "invalid project policy yaml: {error}"),
            Self::InvalidGlob { rule_id, source } => {
                write!(
                    formatter,
                    "invalid glob pattern in asset rule '{rule_id}': {source}"
                )
            }
        }
    }
}

impl std::error::Error for ProjectPolicyError {}

impl From<serde_yml::Error> for ProjectPolicyError {
    fn from(error: serde_yml::Error) -> Self {
        Self::InvalidYaml(error)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicy {
    #[serde(default = "default_project_config")]
    pub project: ProjectConfig,
    #[serde(default = "default_asset_rules")]
    pub assets: Vec<AssetRule>,
    #[serde(default = "default_action_rules")]
    pub actions: BTreeMap<String, ActionRule>,
    #[serde(skip)]
    pub(crate) compiled_asset_globs: Vec<GlobSet>,
}

impl PartialEq for ProjectPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.project == other.project
            && self.assets == other.assets
            && self.actions == other.actions
    }
}

impl Eq for ProjectPolicy {}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssetRule {
    pub id: String,
    pub patterns: Vec<String>,
    pub sensitivity: String,
    pub default_action: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionRule {
    pub default_action: String,
}

impl Default for ProjectPolicy {
    fn default() -> Self {
        let assets = default_asset_rules();
        let compiled_asset_globs =
            compile_asset_globs(&assets).expect("built-in default asset glob patterns are valid");
        Self {
            project: default_project_config(),
            assets,
            actions: default_action_rules(),
            compiled_asset_globs,
        }
    }
}

impl ProjectPolicy {
    pub fn load_yaml(yaml: &str) -> Result<Self, ProjectPolicyError> {
        let mut policy: Self = serde_yml::from_str(yaml)?;
        policy.compiled_asset_globs = compile_asset_globs(&policy.assets).map_err(|error| {
            ProjectPolicyError::InvalidGlob {
                rule_id: error.0,
                source: error.1,
            }
        })?;
        Ok(policy)
    }

    pub fn match_asset(&self, target: &str) -> Option<AssetMatch> {
        self.assets
            .iter()
            .zip(self.compiled_asset_globs.iter())
            .find_map(|(asset, glob_set)| {
                if glob_set.is_match(target) {
                    Some(AssetMatch {
                        id: asset.id.clone(),
                        sensitivity: asset.sensitivity.clone(),
                        default_action: asset.default_action.clone(),
                    })
                } else {
                    None
                }
            })
    }
}

fn compile_asset_globs(assets: &[AssetRule]) -> Result<Vec<GlobSet>, (String, globset::Error)> {
    assets
        .iter()
        .map(|asset| {
            let mut builder = GlobSetBuilder::new();
            for pattern in &asset.patterns {
                let glob = Glob::new(pattern).map_err(|error| (asset.id.clone(), error))?;
                builder.add(glob);
            }
            builder.build().map_err(|error| (asset.id.clone(), error))
        })
        .collect()
}

fn default_project_config() -> ProjectConfig {
    ProjectConfig {
        name: String::from("descry"),
    }
}

fn default_schema_version() -> u32 {
    1
}

fn default_pack_version() -> String {
    String::from("local")
}

fn default_asset_rules() -> Vec<AssetRule> {
    vec![
        AssetRule {
            id: String::from("secrets"),
            patterns: vec![
                String::from(".env*"),
                String::from("**/*secret*"),
                String::from("**/*token*"),
                String::from("~/.ssh/**"),
            ],
            sensitivity: String::from("critical"),
            default_action: String::from("block"),
        },
        AssetRule {
            id: String::from("infra"),
            patterns: vec![
                String::from("infra/**"),
                String::from("terraform/**"),
                String::from(".github/workflows/**"),
                String::from("scripts/deploy/**"),
            ],
            sensitivity: String::from("high"),
            default_action: String::from("require_approval"),
        },
        AssetRule {
            id: String::from("source"),
            patterns: vec![
                String::from("src/**"),
                String::from("tests/**"),
                String::from("crates/**"),
            ],
            sensitivity: String::from("normal"),
            default_action: String::from("allow_if_context_matches"),
        },
    ]
}

fn default_action_rules() -> BTreeMap<String, ActionRule> {
    BTreeMap::from([
        (
            String::from("destructive"),
            ActionRule {
                default_action: String::from("block"),
            },
        ),
        (
            String::from("deploy"),
            ActionRule {
                default_action: String::from("require_approval"),
            },
        ),
        (
            String::from("test"),
            ActionRule {
                default_action: String::from("allow"),
            },
        ),
        (
            String::from("build"),
            ActionRule {
                default_action: String::from("allow"),
            },
        ),
        (
            String::from("install"),
            ActionRule {
                default_action: String::from("require_approval"),
            },
        ),
        (
            String::from("git_rewrite"),
            ActionRule {
                default_action: String::from("require_approval"),
            },
        ),
        (
            String::from("mcp_write"),
            ActionRule {
                default_action: String::from("require_approval"),
            },
        ),
    ])
}
