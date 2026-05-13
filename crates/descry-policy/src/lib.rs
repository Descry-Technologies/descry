mod evaluate;
mod matcher;
mod types;

use std::error::Error;
use std::fmt;

use matcher::CompiledHardBlock;

pub use types::{ActionRule, AssetRule, HardBlock, Policy, Project, ProjectConfig, ProjectPolicy};

#[derive(Debug)]
pub enum PolicyError {
    InvalidYaml(serde_yml::Error),
    InvalidRegex {
        rule_id: String,
        source: regex::Error,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(formatter, "invalid policy yaml: {error}"),
            Self::InvalidRegex { rule_id, source } => {
                write!(formatter, "invalid regex in rule {rule_id}: {source}")
            }
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidYaml(error) => Some(error),
            Self::InvalidRegex { source, .. } => Some(source),
        }
    }
}

impl From<serde_yml::Error> for PolicyError {
    fn from(error: serde_yml::Error) -> Self {
        Self::InvalidYaml(error)
    }
}

impl Policy {
    pub fn load_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let mut policy: Self = serde_yml::from_str(yaml)?;
        policy.compiled_hard_blocks = policy
            .hard_blocks
            .iter()
            .map(CompiledHardBlock::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(policy)
    }
}
