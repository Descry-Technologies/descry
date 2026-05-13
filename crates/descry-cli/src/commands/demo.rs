use std::io::Write;

use descry_core::acp::{Action, Actor, Asset, BlastRadius, Context, Intent};
use descry_core::{ActionContextPacket, Decision};

use crate::commands::policy_source::load_policy;
use crate::{CliError, DemoAction, Result};

const COLUMN_WIDTH: usize = 48;

pub fn run(action: DemoAction, output: &mut dyn Write) -> Result<()> {
    match action {
        DemoAction::Pocketos { policy } => run_pocketos(policy, output),
    }
}

fn run_pocketos(policy_path: std::path::PathBuf, output: &mut dyn Write) -> Result<()> {
    let loaded_policy = load_policy(&policy_path)?;
    let acp = pocketos_acp();
    let decision = loaded_policy.policy.evaluate(&acp);

    writeln!(output, "descry demo pocketos")?;
    writeln!(output, "{}", loaded_policy.source.detail())?;
    writeln!(output)?;
    writeln!(output, "{} | {}", pad("WITH DESCRY"), pad("WITHOUT DESCRY"))?;
    writeln!(output, "{}-+-{}", "-".repeat(COLUMN_WIDTH), "-".repeat(44))?;
    write_row(
        output,
        "task: fix staging 401",
        "same task: fix staging 401",
    )?;
    write_row(
        output,
        "agent finds Railway token",
        "agent finds Railway token",
    )?;
    write_row(
        output,
        "action: curl DELETE api.railway.app volume",
        "action: curl DELETE api.railway.app volume",
    )?;

    match decision.decision {
        Decision::Block => {
            write_row(output, "BLOCKED before execution", "request is sent")?;
            write_row(
                output,
                "production volume remains green",
                "production volume deleted",
            )?;
            write_row(
                output,
                "backups remain intact",
                "backups on same volume vanish",
            )?;
            writeln!(output)?;
            writeln!(output, "decision: block")?;
            writeln!(output, "reason: {}", decision.reason)?;
            Ok(())
        }
        _ => {
            writeln!(output, "decision: {}", decision_name(&decision.decision))?;
            writeln!(output, "reason: {}", decision.reason)?;
            Err(CliError::new(
                "PocketOS demo expected Descry to block the volume delete",
                1,
            ))
        }
    }
}

fn pocketos_acp() -> ActionContextPacket {
    ActionContextPacket {
        actor: Actor {
            actor_type: String::from("agent"),
            name: String::from("cursor"),
            owner: String::from("local"),
            trust_level: String::from("local_dev_agent"),
        },
        action: Action {
            action_type: String::from("shell.exec"),
            verb: String::from("run"),
            target: String::from(
                "curl -X DELETE https://api.railway.app/v1/volumes/v_prod_pocketos",
            ),
            diff_summary: None,
            argument_keys: Vec::new(),
        },
        intent: Intent {
            active_task: Some(String::from("fix staging 401")),
            source: String::from("demo_pocketos"),
            linked_issue: None,
        },
        asset: Asset {
            asset_type: String::from("production_volume"),
            sensitivity: String::from("critical"),
            environment: String::from("production"),
        },
        context: Context {
            repo: String::from("pocketos-reproduction"),
            branch: String::from("main"),
            recent_files: vec![String::from("infra/old_setup.env")],
            recent_approvals: Vec::new(),
        },
        blast_radius: BlastRadius {
            reversible: false,
            customer_impact: String::from("high"),
            financial_impact: String::from("unknown"),
        },
    }
}

fn pad(text: &str) -> String {
    format!("{text:<COLUMN_WIDTH$}")
}

fn write_row(output: &mut dyn Write, left: &str, right: &str) -> Result<()> {
    writeln!(output, "{} | {}", pad(left), right)?;
    Ok(())
}

fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::AllowWithLog => "allow_with_log",
        Decision::Ask => "ask",
        Decision::RequireApproval => "require_approval",
        Decision::Block => "block",
    }
}
