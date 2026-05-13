use descry_core::{ActionContextPacket, Confidence, Decision, DecisionOutput, RiskScore};

use crate::matcher::match_action;
use crate::Policy;

impl Policy {
    pub fn evaluate(&self, acp: &ActionContextPacket) -> DecisionOutput {
        if let Some(block) = match_action(
            &acp.action.action_type,
            &acp.action.target,
            acp.action.diff_summary.as_deref(),
            &acp.action.argument_keys,
            &self.compiled_hard_blocks,
        ) {
            return DecisionOutput {
                decision: Decision::Block,
                risk_score: RiskScore::try_from(100).expect("100 is a valid risk score"),
                confidence: Confidence::try_from(0.98).expect("0.98 is a valid confidence"),
                reason: format!("{} (rule: {})", block.reason, block.id),
                conditions: Vec::new(),
            };
        }

        DecisionOutput {
            decision: Decision::Allow,
            risk_score: RiskScore::try_from(0).expect("zero is a valid risk score"),
            confidence: Confidence::try_from(1.0).expect("one is a valid confidence"),
            reason: String::from("no hard-block matched (Tier-1 only at DG-003)"),
            conditions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use descry_core::{ActionContextPacket, Decision};

    use crate::Policy;

    fn acp(action_type: &str, target: &str) -> ActionContextPacket {
        serde_yml::from_str(&format!(
            r#"{{
  "actor": {{
    "type": "agent",
    "name": "claude-code",
    "owner": "maciej",
    "trust_level": "local_dev_agent"
  }},
    "action": {{
      "type": "{action_type}",
      "verb": "run",
      "target": "{target}",
      "diff_summary": null,
      "argument_keys": []
    }},
  "intent": {{
    "active_task": "DG-003",
    "source": "user_prompt",
    "linked_issue": null
  }},
  "asset": {{
    "type": "code_file",
    "sensitivity": "low",
    "environment": "local"
  }},
  "context": {{
    "repo": "descry",
    "branch": "dg-003",
    "recent_files": [],
    "recent_approvals": []
  }},
  "blast_radius": {{
    "reversible": true,
    "customer_impact": "none",
    "financial_impact": "none"
  }}
}}"#
        ))
        .expect("test ACP deserializes")
    }

    #[test]
    fn blocks_matching_shell_command() {
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: rm-root-home
    action: shell.exec
    command_matches:
      - "rm -rf /"
    command_regex: null
    reason: destructive root deletion
"#,
        )
        .expect("policy loads");

        let decision = policy.evaluate(&acp("shell.exec", "rm -rf /"));

        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(
            decision.reason,
            "destructive root deletion (rule: rm-root-home)"
        );
    }

    #[test]
    fn allows_non_matching_command() {
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: rm-root-home
    action: shell.exec
    command_matches:
      - "rm -rf /"
    command_regex: null
    reason: destructive root deletion
"#,
        )
        .expect("policy loads");

        let decision = policy.evaluate(&acp("shell.exec", "cargo test -p descry-core"));

        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(
            decision.reason,
            "no hard-block matched (Tier-1 only at DG-003)"
        );
    }

    #[test]
    fn blocks_matching_mcp_target() {
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: mcp-production-control-plane
    action: mcp.call
    command_matches:
      - "prod-mcp"
    command_regex: null
    reason: production MCP control-plane access
"#,
        )
        .expect("policy loads");

        let decision = policy.evaluate(&acp("mcp.call", "https://prod-mcp.example.com/mcp"));

        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(
            decision.reason,
            "production MCP control-plane access (rule: mcp-production-control-plane)"
        );
    }

    #[test]
    fn blocks_matching_mcp_summary() {
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: mcp-destructive-tool
    action: mcp.call
    summary_matches:
      - "delete_project"
    reason: destructive MCP tool
"#,
        )
        .expect("policy loads");

        let mut acp = acp("mcp.call", "https://mcp.example.com/readonly");
        acp.action.diff_summary = Some(String::from("Cursor MCP tool call: delete_project"));
        let decision = policy.evaluate(&acp);

        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(
            decision.reason,
            "destructive MCP tool (rule: mcp-destructive-tool)"
        );
    }

    #[test]
    fn blocks_matching_mcp_argument_key() {
        let policy = Policy::load_yaml(
            r#"
project:
  name: test
  version: "1"
hard_blocks:
  - id: mcp-dangerous-argument
    action: mcp.call
    argument_key_matches:
      - "confirm_destroy"
    reason: dangerous MCP argument key
"#,
        )
        .expect("policy loads");

        let mut acp = acp("mcp.call", "https://mcp.example.com/readonly");
        acp.action.argument_keys = vec![String::from("confirm_destroy")];
        let decision = policy.evaluate(&acp);

        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(
            decision.reason,
            "dangerous MCP argument key (rule: mcp-dangerous-argument)"
        );
    }
}
