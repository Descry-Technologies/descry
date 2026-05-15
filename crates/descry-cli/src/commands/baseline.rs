use std::io::Write;

use serde_json::json;

use crate::{BaselineAction, CliError, Result};

pub fn run(action: BaselineAction, output: &mut dyn Write) -> Result<()> {
    match action {
        BaselineAction::Explain {
            agent,
            action: action_type,
            target,
            behavior,
        } => {
            let count = descry_memory::behavior_count(&behavior, &agent, &action_type, &target)
                .unwrap_or(0);

            let (familiarity, note) = match count {
                0 => (
                    "unseen",
                    "This exact (agent, action, target) triple has never been recorded. The engine has no behavioral baseline for it.",
                ),
                1..=2 => (
                    "rare",
                    "Seen only once or twice. The engine treats this as low-confidence baseline; drift signals carry more weight.",
                ),
                3..=9 => (
                    "occasional",
                    "Seen a handful of times. A modest behavioral baseline exists.",
                ),
                _ => (
                    "familiar",
                    "Seen 10+ times. Strong behavioral baseline; repeated-action escalation thresholds apply.",
                ),
            };

            writeln!(
                output,
                "{}",
                json!({
                    "agent": agent,
                    "action": action_type,
                    "target": target,
                    "observed_count": count,
                    "familiarity": familiarity,
                    "note": note,
                })
            )
            .map_err(|e| CliError::new(e.to_string(), 1))
        }
    }
}
