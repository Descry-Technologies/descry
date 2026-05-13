use std::fs;
use std::path::{Path, PathBuf};

use descry_policy::Policy;

use crate::{CliError, Result};

pub(crate) const DEFAULT_POLICY_PATH: &str = "policies/safe-defaults.yml";
const BUILT_IN_SAFE_DEFAULTS: &str = include_str!("../../../../policies/safe-defaults.yml");

pub(crate) struct LoadedPolicy {
    pub policy: Policy,
    pub source: PolicySource,
}

pub(crate) enum PolicySource {
    File(PathBuf),
    BuiltInSafeDefaults,
}

pub(crate) fn load_policy(path: &Path) -> Result<LoadedPolicy> {
    match fs::read_to_string(path) {
        Ok(body) => parse_policy(&body, PolicySource::File(path.to_path_buf())),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && path == Path::new(DEFAULT_POLICY_PATH) =>
        {
            parse_policy(BUILT_IN_SAFE_DEFAULTS, PolicySource::BuiltInSafeDefaults)
        }
        Err(error) => Err(CliError::new(
            format!("failed to read policy {}: {error}", path.display()),
            2,
        )),
    }
}

fn parse_policy(body: &str, source: PolicySource) -> Result<LoadedPolicy> {
    let policy = Policy::load_yaml(body)
        .map_err(|error| CliError::new(format!("failed to load policy: {error}"), 2))?;
    Ok(LoadedPolicy { policy, source })
}

impl PolicySource {
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::File(path) => format!("loaded {}", path.display()),
            Self::BuiltInSafeDefaults => String::from("loaded built-in safe-defaults policy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{load_policy, PolicySource, DEFAULT_POLICY_PATH};

    #[test]
    fn falls_back_to_built_in_safe_defaults_for_missing_default_path() {
        let loaded = load_policy(Path::new(DEFAULT_POLICY_PATH)).expect("policy loads");

        assert!(!loaded.policy.hard_blocks.is_empty());
    }

    #[test]
    fn does_not_fallback_for_custom_missing_policy() {
        let error = match load_policy(Path::new("missing-custom-policy.yml")) {
            Ok(_) => panic!("custom missing policy should fail"),
            Err(error) => error,
        };

        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn source_detail_is_human_readable() {
        assert_eq!(
            PolicySource::BuiltInSafeDefaults.detail(),
            "loaded built-in safe-defaults policy"
        );
    }
}
