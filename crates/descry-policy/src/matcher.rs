use regex::Regex;

use crate::{HardBlock, PolicyError};

#[derive(Clone, Debug)]
pub(crate) struct CompiledHardBlock {
    pub(crate) id: String,
    pub(crate) action: String,
    pub(crate) target_regexes: Vec<Regex>,
    pub(crate) target_substrings: Vec<String>,
    pub(crate) summary_regex: Option<Regex>,
    pub(crate) summary_substrings: Vec<String>,
    pub(crate) argument_key_regex: Option<Regex>,
    pub(crate) argument_key_matches: Vec<String>,
    pub(crate) sql_delete_without_where: bool,
    pub(crate) reason: String,
}

impl TryFrom<&HardBlock> for CompiledHardBlock {
    type Error = PolicyError;

    fn try_from(block: &HardBlock) -> Result<Self, Self::Error> {
        let mut target_regexes = Vec::new();
        if let Some(regex) = compile_optional_regex(&block.id, block.command_regex.as_deref())? {
            target_regexes.push(regex);
        }
        if let Some(regex) = compile_optional_regex(&block.id, block.target_regex.as_deref())? {
            target_regexes.push(regex);
        }
        let summary_regex = compile_optional_regex(&block.id, block.summary_regex.as_deref())?;
        let argument_key_regex =
            compile_optional_regex(&block.id, block.argument_key_regex.as_deref())?;
        let mut target_substrings = block.command_matches.clone();
        target_substrings.extend(block.target_matches.clone());

        Ok(Self {
            id: block.id.clone(),
            action: block.action.clone(),
            target_regexes,
            target_substrings,
            summary_regex,
            summary_substrings: block.summary_matches.clone(),
            argument_key_regex,
            argument_key_matches: block.argument_key_matches.clone(),
            sql_delete_without_where: block.sql_delete_without_where,
            reason: block.reason.clone(),
        })
    }
}

pub(crate) fn match_action<'a>(
    action: &str,
    target: &str,
    summary: Option<&str>,
    argument_keys: &[String],
    compiled_blocks: &'a [CompiledHardBlock],
) -> Option<&'a CompiledHardBlock> {
    compiled_blocks
        .iter()
        .filter(|block| block.action == action)
        .find(|block| block.matches(target, summary, argument_keys))
}

fn compile_optional_regex(
    rule_id: &str,
    pattern: Option<&str>,
) -> Result<Option<Regex>, PolicyError> {
    pattern
        .map(Regex::new)
        .transpose()
        .map_err(|source| PolicyError::InvalidRegex {
            rule_id: rule_id.to_string(),
            source,
        })
}

impl CompiledHardBlock {
    fn matches(&self, target: &str, summary: Option<&str>, argument_keys: &[String]) -> bool {
        self.target_substrings
            .iter()
            .any(|substring| target.contains(substring))
            || self
                .target_regexes
                .iter()
                .any(|regex| regex.is_match(target))
            || summary.is_some_and(|summary| self.matches_summary(summary))
            || self.matches_argument_key(argument_keys)
            || (self.sql_delete_without_where && has_delete_without_where(target))
    }

    fn matches_summary(&self, summary: &str) -> bool {
        self.summary_substrings
            .iter()
            .any(|substring| summary.contains(substring))
            || self
                .summary_regex
                .as_ref()
                .is_some_and(|regex| regex.is_match(summary))
    }

    fn matches_argument_key(&self, argument_keys: &[String]) -> bool {
        argument_keys.iter().any(|argument_key| {
            self.argument_key_matches
                .iter()
                .any(|expected| expected == argument_key)
                || self
                    .argument_key_regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(argument_key))
        })
    }
}

fn has_delete_without_where(text: &str) -> bool {
    sanitized_sql_statements(text)
        .into_iter()
        .any(|statement| statement_contains_delete_without_where(&statement))
}

fn sanitized_sql_statements(text: &str) -> Vec<String> {
    strip_sql_comments(text)
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_string)
        .collect()
}

fn strip_sql_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(character) = chars.next() {
        if in_line_comment {
            if character == '\n' {
                in_line_comment = false;
                output.push(' ');
            }
            continue;
        }

        if in_block_comment {
            if character == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
                output.push(' ');
            }
            continue;
        }

        if character == '-' && chars.peek() == Some(&'-') {
            chars.next();
            in_line_comment = true;
            output.push(' ');
        } else if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            output.push(' ');
        } else {
            output.push(character);
        }
    }

    output
}

fn statement_contains_delete_without_where(statement: &str) -> bool {
    let lowercase = statement.to_ascii_lowercase();
    let Some(delete_index) = lowercase.find("delete") else {
        return false;
    };
    let after_delete = &lowercase[delete_index + "delete".len()..];
    let trimmed = after_delete.trim_start();
    if !trimmed.starts_with("from") {
        return false;
    }
    let after_from = &trimmed["from".len()..];
    if after_from.trim().is_empty() {
        return false;
    }

    !contains_word(after_from, "where")
}

fn contains_word(text: &str, word: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|part| part == word)
}

#[cfg(test)]
mod tests {
    use super::match_action;
    use super::CompiledHardBlock;
    use crate::{HardBlock, PolicyError};

    #[test]
    fn compiles_valid_regex() {
        let block = HardBlock {
            id: String::from("valid"),
            action: String::from("shell.exec"),
            command_matches: Vec::new(),
            command_regex: Some(String::from(r"^git\s+push")),
            target_matches: Vec::new(),
            target_regex: None,
            summary_matches: Vec::new(),
            summary_regex: None,
            argument_key_matches: Vec::new(),
            argument_key_regex: None,
            sql_delete_without_where: false,
            reason: String::from("protected branch update"),
        };

        let compiled = CompiledHardBlock::try_from(&block).expect("regex compiles");

        assert_eq!(compiled.target_regexes.len(), 1);
    }

    #[test]
    fn surfaces_invalid_regex_with_rule_id() {
        let block = HardBlock {
            id: String::from("bad-regex"),
            action: String::from("shell.exec"),
            command_matches: Vec::new(),
            command_regex: Some(String::from("[")),
            target_matches: Vec::new(),
            target_regex: None,
            summary_matches: Vec::new(),
            summary_regex: None,
            argument_key_matches: Vec::new(),
            argument_key_regex: None,
            sql_delete_without_where: false,
            reason: String::from("bad regex"),
        };

        let error = CompiledHardBlock::try_from(&block).expect_err("regex fails");

        assert!(matches!(
            error,
            PolicyError::InvalidRegex { ref rule_id, .. } if rule_id == "bad-regex"
        ));
    }

    #[test]
    fn matches_non_shell_actions_by_target() {
        let block = CompiledHardBlock {
            id: String::from("mcp-prod"),
            action: String::from("mcp.call"),
            target_regexes: Vec::new(),
            target_substrings: vec![String::from("prod-mcp")],
            summary_regex: None,
            summary_substrings: Vec::new(),
            argument_key_regex: None,
            argument_key_matches: Vec::new(),
            sql_delete_without_where: false,
            reason: String::from("production MCP"),
        };

        let blocks = [block];
        let matched = match_action(
            "mcp.call",
            "https://prod-mcp.example.com",
            None,
            &[],
            &blocks,
        )
        .expect("block matches");

        assert_eq!(matched.id, "mcp-prod");
    }

    #[test]
    fn matches_summary_substrings() {
        let block = CompiledHardBlock {
            id: String::from("mcp-tool"),
            action: String::from("mcp.call"),
            target_regexes: Vec::new(),
            target_substrings: Vec::new(),
            summary_regex: None,
            summary_substrings: vec![String::from("delete_project")],
            argument_key_regex: None,
            argument_key_matches: Vec::new(),
            sql_delete_without_where: false,
            reason: String::from("destructive MCP tool"),
        };

        let blocks = [block];
        let matched = match_action(
            "mcp.call",
            "https://mcp.example.com/readonly",
            Some("Cursor MCP tool call: delete_project"),
            &[],
            &blocks,
        )
        .expect("block matches");

        assert_eq!(matched.id, "mcp-tool");
    }

    #[test]
    fn matches_argument_keys() {
        let block = CompiledHardBlock {
            id: String::from("mcp-arg"),
            action: String::from("mcp.call"),
            target_regexes: Vec::new(),
            target_substrings: Vec::new(),
            summary_regex: None,
            summary_substrings: Vec::new(),
            argument_key_regex: None,
            argument_key_matches: vec![String::from("confirm_destroy")],
            sql_delete_without_where: false,
            reason: String::from("dangerous MCP argument"),
        };

        let blocks = [block];
        let argument_keys = vec![String::from("confirm_destroy")];
        let matched = match_action(
            "mcp.call",
            "https://mcp.example.com/readonly",
            None,
            &argument_keys,
            &blocks,
        )
        .expect("block matches");

        assert_eq!(matched.id, "mcp-arg");
    }

    #[test]
    fn matches_delete_from_without_where() {
        let block = CompiledHardBlock {
            id: String::from("sql-delete"),
            action: String::from("shell.exec"),
            target_regexes: Vec::new(),
            target_substrings: Vec::new(),
            summary_regex: None,
            summary_substrings: Vec::new(),
            argument_key_regex: None,
            argument_key_matches: Vec::new(),
            sql_delete_without_where: true,
            reason: String::from("unbounded SQL delete"),
        };

        let blocks = [block];
        let matched = match_action(
            "shell.exec",
            "psql \"$DATABASE_URL\" -c 'DELETE FROM users'",
            None,
            &[],
            &blocks,
        )
        .expect("block matches");

        assert_eq!(matched.id, "sql-delete");
    }

    #[test]
    fn allows_delete_from_with_where() {
        let block = CompiledHardBlock {
            id: String::from("sql-delete"),
            action: String::from("shell.exec"),
            target_regexes: Vec::new(),
            target_substrings: Vec::new(),
            summary_regex: None,
            summary_substrings: Vec::new(),
            argument_key_regex: None,
            argument_key_matches: Vec::new(),
            sql_delete_without_where: true,
            reason: String::from("unbounded SQL delete"),
        };

        let blocks = [block];
        let matched = match_action(
            "shell.exec",
            "psql \"$DATABASE_URL\" -c 'DELETE FROM users WHERE id = 42'",
            None,
            &[],
            &blocks,
        );

        assert!(matched.is_none());
    }
}
