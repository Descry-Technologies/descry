use std::collections::BTreeMap;

use descry_core::AssetMatch;
use regex::Regex;
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicy {
    #[serde(default = "default_project_config")]
    pub project: ProjectConfig,
    #[serde(default = "default_asset_rules")]
    pub assets: Vec<AssetRule>,
    #[serde(default = "default_action_rules")]
    pub actions: BTreeMap<String, ActionRule>,
}

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
        Self {
            project: default_project_config(),
            assets: default_asset_rules(),
            actions: default_action_rules(),
        }
    }
}

impl ProjectPolicy {
    pub fn load_yaml(yaml: &str) -> Result<Self, serde_yml::Error> {
        serde_yml::from_str(yaml)
    }

    pub fn match_asset(&self, target: &str) -> Option<AssetMatch> {
        self.assets.iter().find_map(|asset| {
            if asset
                .patterns
                .iter()
                .any(|pattern| glob_matches(pattern, target))
            {
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

fn glob_matches(pattern: &str, target: &str) -> bool {
    let regex = glob_to_regex(pattern);
    Regex::new(&regex).is_ok_and(|regex| regex.is_match(target))
}

fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    regex.push_str("(?:.*/)?");
                } else {
                    regex.push_str(".*");
                }
            }
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push_str("[^/]"),
            _ => regex.push_str(&regex::escape(&character.to_string())),
        }
    }

    regex.push('$');
    regex
}
