mod evaluate;
mod matcher;
mod types;

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use matcher::CompiledHardBlock;

pub use types::{
    ActionRule, AssetRule, HardBlock, Policy, Project, ProjectConfig, ProjectPolicy,
    ProjectPolicyError,
};

#[derive(Debug)]
pub enum PolicyError {
    InvalidYaml(serde_yml::Error),
    UnsupportedSchemaVersion(u32),
    DuplicateRuleId(String),
    EmptyRuleId,
    EmptyReason {
        rule_id: String,
    },
    InvalidRegex {
        rule_id: String,
        source: regex::Error,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(formatter, "invalid policy yaml: {error}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported policy schema_version {version}")
            }
            Self::DuplicateRuleId(rule_id) => write!(formatter, "duplicate rule id {rule_id}"),
            Self::EmptyRuleId => write!(formatter, "policy hard block has an empty rule id"),
            Self::EmptyReason { rule_id } => {
                write!(formatter, "policy hard block {rule_id} has an empty reason")
            }
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
            Self::UnsupportedSchemaVersion(_)
            | Self::DuplicateRuleId(_)
            | Self::EmptyRuleId
            | Self::EmptyReason { .. } => None,
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
        validate_policy(&policy)?;
        policy.compiled_hard_blocks = policy
            .hard_blocks
            .iter()
            .map(CompiledHardBlock::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(policy)
    }
}

fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    if policy.schema_version != 1 {
        return Err(PolicyError::UnsupportedSchemaVersion(policy.schema_version));
    }

    let mut ids = HashSet::new();
    for block in &policy.hard_blocks {
        let rule_id = block.id.trim();
        if rule_id.is_empty() {
            return Err(PolicyError::EmptyRuleId);
        }
        if !ids.insert(rule_id.to_string()) {
            return Err(PolicyError::DuplicateRuleId(rule_id.to_string()));
        }
        if block.reason.trim().is_empty() {
            return Err(PolicyError::EmptyReason {
                rule_id: rule_id.to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Policy, PolicyError};

    fn policy_yaml(extra: &str) -> String {
        format!(
            r#"
schema_version: 1
pack_version: "0.1.0"
project:
  name: test
  version: "1"
hard_blocks:
  - id: rm-root
    action: shell.exec
    command_matches:
      - "rm -rf /"
    reason: destructive root deletion
{extra}
"#
        )
    }

    #[test]
    fn loads_versioned_policy_schema() {
        let policy = Policy::load_yaml(&policy_yaml("")).expect("policy loads");

        assert_eq!(policy.schema_version, 1);
        assert_eq!(policy.pack_version, "0.1.0");
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let yaml = policy_yaml("").replace("schema_version: 1", "schema_version: 2");

        let error = Policy::load_yaml(&yaml).expect_err("schema version fails");

        assert!(matches!(error, PolicyError::UnsupportedSchemaVersion(2)));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let yaml = policy_yaml(
            r#"
  - id: rm-root
    action: shell.exec
    command_matches:
      - "sudo rm -rf /"
    reason: duplicate id
"#,
        );

        let error = Policy::load_yaml(&yaml).expect_err("duplicate ids fail");

        assert!(matches!(error, PolicyError::DuplicateRuleId(rule_id) if rule_id == "rm-root"));
    }

    #[test]
    fn rejects_empty_rule_ids_and_reasons() {
        let empty_id = policy_yaml("").replace("id: rm-root", "id: ''");
        let empty_reason =
            policy_yaml("").replace("reason: destructive root deletion", "reason: ''");

        assert!(matches!(
            Policy::load_yaml(&empty_id).expect_err("empty id fails"),
            PolicyError::EmptyRuleId
        ));
        assert!(matches!(
            Policy::load_yaml(&empty_reason).expect_err("empty reason fails"),
            PolicyError::EmptyReason { rule_id } if rule_id == "rm-root"
        ));
    }

    #[test]
    fn rejects_unknown_policy_fields() {
        let yaml =
            policy_yaml("").replace("pack_version:", "unexpected_field: true\npack_version:");

        let error = Policy::load_yaml(&yaml).expect_err("unknown fields fail");

        assert!(matches!(error, PolicyError::InvalidYaml(_)));
    }
}
