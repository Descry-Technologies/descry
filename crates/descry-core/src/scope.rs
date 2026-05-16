use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ActionClass;

const SIGNATURE_ALGORITHM: &str = "sha256:descry-scope-v1";
const HMAC_ALGORITHM: &str = "hmac-sha256:descry-scope-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ActiveTask,
    UserPrompt,
    Branch,
    RecentFile,
    ProjectIndex,
    Codeowners,
    StaticPolicy,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub source: EvidenceSource,
    pub id: String,
    pub summary: String,
}

impl EvidenceRef {
    pub fn new(source: EvidenceSource, id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            source,
            id: sanitize_text(&id.into()),
            summary: sanitize_text(&summary.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopePermitKind {
    Path,
    Asset,
    Action,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePermit {
    pub kind: ScopePermitKind,
    pub pattern: String,
    pub action_classes: Vec<ActionClass>,
    pub reason: String,
}

impl ScopePermit {
    pub fn new(
        kind: ScopePermitKind,
        pattern: impl Into<String>,
        action_classes: Vec<ActionClass>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            pattern: sanitize_text(&pattern.into()),
            action_classes,
            reason: sanitize_text(&reason.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSignature {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeContract {
    pub id: String,
    pub version: u32,
    pub task_summary: String,
    pub evidence: Vec<EvidenceRef>,
    pub permits: Vec<ScopePermit>,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub confidence: f32,
    pub signature: ScopeSignature,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedScopeContract {
    version: u32,
    task_summary: String,
    evidence: Vec<EvidenceRef>,
    permits: Vec<ScopePermit>,
    created_at_epoch_seconds: u64,
    expires_at_epoch_seconds: u64,
    confidence: f32,
}

impl ScopeContract {
    /// Create a scope contract signed with keyless SHA-256 (backward-compatible default).
    /// For new deployments prefer `signed_keyed` which uses HMAC-SHA256 with a machine secret.
    pub fn signed(
        task_summary: impl Into<String>,
        evidence: Vec<EvidenceRef>,
        permits: Vec<ScopePermit>,
        created_at_epoch_seconds: u64,
        expires_at_epoch_seconds: u64,
        confidence: f32,
    ) -> Result<Self, ScopeContractError> {
        Self::signed_inner(
            task_summary,
            evidence,
            permits,
            created_at_epoch_seconds,
            expires_at_epoch_seconds,
            confidence,
            None,
        )
    }

    /// Create a scope contract signed with HMAC-SHA256 keyed on `signing_key`.
    ///
    /// The key should be loaded from `~/.descry/signing.key` (generated at `descry init`).
    /// A contract signed with a key can only be verified with the same key — contracts are
    /// machine-scoped, which prevents cross-machine approval replay.
    pub fn signed_keyed(
        task_summary: impl Into<String>,
        evidence: Vec<EvidenceRef>,
        permits: Vec<ScopePermit>,
        created_at_epoch_seconds: u64,
        expires_at_epoch_seconds: u64,
        confidence: f32,
        signing_key: &[u8],
    ) -> Result<Self, ScopeContractError> {
        Self::signed_inner(
            task_summary,
            evidence,
            permits,
            created_at_epoch_seconds,
            expires_at_epoch_seconds,
            confidence,
            Some(signing_key),
        )
    }

    fn signed_inner(
        task_summary: impl Into<String>,
        evidence: Vec<EvidenceRef>,
        permits: Vec<ScopePermit>,
        created_at_epoch_seconds: u64,
        expires_at_epoch_seconds: u64,
        confidence: f32,
        signing_key: Option<&[u8]>,
    ) -> Result<Self, ScopeContractError> {
        let unsigned = unsigned_contract(
            task_summary,
            evidence,
            permits,
            created_at_epoch_seconds,
            expires_at_epoch_seconds,
            confidence,
        )?;
        let payload = canonical_payload(&unsigned)?;
        let payload_hash = sha256_hex(&payload);
        let signature = match signing_key {
            Some(key) if !key.is_empty() => sign_payload_keyed(&payload, key),
            _ => sign_payload(&payload),
        };

        Ok(Self {
            id: payload_hash.chars().take(32).collect(),
            version: unsigned.version,
            task_summary: unsigned.task_summary,
            evidence: unsigned.evidence,
            permits: unsigned.permits,
            created_at_epoch_seconds: unsigned.created_at_epoch_seconds,
            expires_at_epoch_seconds: unsigned.expires_at_epoch_seconds,
            confidence: unsigned.confidence,
            signature,
        })
    }

    pub fn is_live_at(&self, now_epoch_seconds: u64) -> bool {
        self.expires_at_epoch_seconds > now_epoch_seconds
    }

    /// Verify using keyless SHA-256 (for contracts created with `signed()`).
    pub fn verify_signature(&self) -> bool {
        self.expected_signature()
            .is_ok_and(|expected| expected == self.signature)
            && self
                .expected_id()
                .is_ok_and(|expected_id| expected_id == self.id)
    }

    /// Verify using HMAC-SHA256 (for contracts created with `signed_keyed()`).
    pub fn verify_signature_keyed(&self, signing_key: &[u8]) -> bool {
        let Ok(unsigned) = self.unsigned() else {
            return false;
        };
        let Ok(payload) = canonical_payload(&unsigned) else {
            return false;
        };
        let expected_sig = sign_payload_keyed(&payload, signing_key);
        let expected_id = sha256_hex(&payload).chars().take(32).collect::<String>();
        expected_sig == self.signature && expected_id == self.id
    }

    pub fn resigned_with_expiry(
        &self,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, ScopeContractError> {
        Self::signed(
            self.task_summary.clone(),
            self.evidence.clone(),
            self.permits.clone(),
            self.created_at_epoch_seconds,
            expires_at_epoch_seconds,
            self.confidence,
        )
    }

    fn expected_signature(&self) -> Result<ScopeSignature, ScopeContractError> {
        Ok(sign_payload(&canonical_payload(&self.unsigned()?)?))
    }

    fn expected_id(&self) -> Result<String, ScopeContractError> {
        Ok(sha256_hex(&canonical_payload(&self.unsigned()?)?)
            .chars()
            .take(32)
            .collect())
    }

    fn unsigned(&self) -> Result<UnsignedScopeContract, ScopeContractError> {
        unsigned_contract(
            self.task_summary.clone(),
            self.evidence.clone(),
            self.permits.clone(),
            self.created_at_epoch_seconds,
            self.expires_at_epoch_seconds,
            self.confidence,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeContractError {
    ExpiryBeforeCreation,
    ConfidenceOutOfRange,
    EmptyEvidence,
    EmptyPermits,
    EmptyPermitPattern,
    EmptyPermitActions,
    Serialization(String),
}

impl std::fmt::Display for ScopeContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpiryBeforeCreation => {
                formatter.write_str("scope contract expiry must be after creation")
            }
            Self::ConfidenceOutOfRange => {
                formatter.write_str("scope contract confidence must be between 0.0 and 1.0")
            }
            Self::EmptyEvidence => formatter.write_str("scope contract evidence cannot be empty"),
            Self::EmptyPermits => formatter.write_str("scope contract permits cannot be empty"),
            Self::EmptyPermitPattern => formatter.write_str("scope permit pattern cannot be empty"),
            Self::EmptyPermitActions => {
                formatter.write_str("scope permit action classes cannot be empty")
            }
            Self::Serialization(reason) => {
                write!(formatter, "scope contract serialization: {reason}")
            }
        }
    }
}

impl std::error::Error for ScopeContractError {}

fn unsigned_contract(
    task_summary: impl Into<String>,
    evidence: Vec<EvidenceRef>,
    permits: Vec<ScopePermit>,
    created_at_epoch_seconds: u64,
    expires_at_epoch_seconds: u64,
    confidence: f32,
) -> Result<UnsignedScopeContract, ScopeContractError> {
    if expires_at_epoch_seconds <= created_at_epoch_seconds {
        return Err(ScopeContractError::ExpiryBeforeCreation);
    }
    if !(0.0..=1.0).contains(&confidence) {
        return Err(ScopeContractError::ConfidenceOutOfRange);
    }

    let evidence = normalize_evidence(evidence);
    if evidence.is_empty() {
        return Err(ScopeContractError::EmptyEvidence);
    }

    let permits = normalize_permits(permits)?;
    if permits.is_empty() {
        return Err(ScopeContractError::EmptyPermits);
    }

    Ok(UnsignedScopeContract {
        version: 1,
        task_summary: sanitize_text(&task_summary.into()),
        evidence,
        permits,
        created_at_epoch_seconds,
        expires_at_epoch_seconds,
        confidence,
    })
}

fn normalize_evidence(evidence: Vec<EvidenceRef>) -> Vec<EvidenceRef> {
    let mut evidence = evidence
        .into_iter()
        .map(|item| EvidenceRef::new(item.source, item.id, item.summary))
        .filter(|item| !item.id.is_empty() || !item.summary.is_empty())
        .collect::<Vec<_>>();
    evidence.sort_by_key(|item| format!("{:?}\x1f{}\x1f{}", item.source, item.id, item.summary));
    evidence.dedup();
    evidence
}

fn normalize_permits(permits: Vec<ScopePermit>) -> Result<Vec<ScopePermit>, ScopeContractError> {
    let mut normalized = Vec::new();
    for permit in permits {
        let mut action_classes = permit.action_classes;
        action_classes.sort_by_key(|class| format!("{class:?}"));
        action_classes.dedup();
        if permit.pattern.trim().is_empty() {
            return Err(ScopeContractError::EmptyPermitPattern);
        }
        if action_classes.is_empty() {
            return Err(ScopeContractError::EmptyPermitActions);
        }
        normalized.push(ScopePermit::new(
            permit.kind,
            permit.pattern,
            action_classes,
            permit.reason,
        ));
    }
    normalized.sort_by_key(|permit| {
        format!(
            "{:?}\x1f{}\x1f{:?}",
            permit.kind, permit.pattern, permit.action_classes
        )
    });
    normalized.dedup();
    Ok(normalized)
}

fn canonical_payload(contract: &UnsignedScopeContract) -> Result<Vec<u8>, ScopeContractError> {
    serde_json::to_vec(contract)
        .map_err(|error| ScopeContractError::Serialization(error.to_string()))
}

fn sign_payload(payload: &[u8]) -> ScopeSignature {
    let mut hasher = Sha256::new();
    hasher.update(SIGNATURE_ALGORITHM.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    ScopeSignature {
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        value: bytes_to_hex(&hasher.finalize()),
    }
}

fn sign_payload_keyed(payload: &[u8], key: &[u8]) -> ScopeSignature {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(HMAC_ALGORITHM.as_bytes());
    mac.update(b"\n");
    mac.update(payload);
    ScopeSignature {
        algorithm: HMAC_ALGORITHM.to_string(),
        value: bytes_to_hex(&mac.finalize().into_bytes()),
    }
}

fn sha256_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    bytes_to_hex(&hasher.finalize())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sanitize_text(value: &str) -> String {
    let trimmed = value.trim();
    if looks_sensitive(trimmed) {
        return String::from("<redacted>");
    }

    trimmed
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}

fn looks_sensitive(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("api_key=")
        || lowercase.contains("secret=")
        || lowercase.contains("token=")
        || lowercase.contains("authorization:")
        || lowercase.contains("-----begin ")
        || lowercase.starts_with("sk-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Vec<EvidenceRef> {
        vec![EvidenceRef::new(
            EvidenceSource::ActiveTask,
            "task:AUTH-241",
            "Fix login session expiry",
        )]
    }

    fn permits() -> Vec<ScopePermit> {
        vec![ScopePermit::new(
            ScopePermitKind::Path,
            "src/auth/**",
            vec![ActionClass::FileWrite, ActionClass::ShellTest],
            "active task references auth session",
        )]
    }

    #[test]
    fn signed_contract_verifies_and_round_trips() {
        let contract =
            ScopeContract::signed("Fix auth session", evidence(), permits(), 100, 200, 0.8)
                .expect("contract signs");

        assert!(contract.verify_signature());
        assert!(contract.is_live_at(150));
        assert!(!contract.is_live_at(200));

        let encoded = serde_json::to_string(&contract).expect("contract serializes");
        let decoded: ScopeContract = serde_json::from_str(&encoded).expect("contract parses");

        assert_eq!(decoded, contract);
        assert!(decoded.verify_signature());
    }

    #[test]
    fn signing_is_stable_after_input_reordering() {
        let mut reversed_evidence = evidence();
        reversed_evidence.push(EvidenceRef::new(
            EvidenceSource::Branch,
            "branch:fix-session",
            "fix-session",
        ));
        let mut sorted_evidence = reversed_evidence.clone();
        sorted_evidence.reverse();

        let first = ScopeContract::signed(
            "Fix auth session",
            reversed_evidence,
            permits(),
            100,
            200,
            0.8,
        )
        .expect("first signs");
        let second = ScopeContract::signed(
            "Fix auth session",
            sorted_evidence,
            permits(),
            100,
            200,
            0.8,
        )
        .expect("second signs");

        assert_eq!(first.id, second.id);
        assert_eq!(first.signature, second.signature);
    }

    #[test]
    fn tampered_contract_fails_verification() {
        let mut contract =
            ScopeContract::signed("Fix auth session", evidence(), permits(), 100, 200, 0.8)
                .expect("contract signs");

        contract.permits[0].pattern = String::from("infra/**");

        assert!(!contract.verify_signature());
    }

    #[test]
    fn constructor_redacts_sensitive_evidence() {
        let contract = ScopeContract::signed(
            "token=super-secret",
            vec![EvidenceRef::new(
                EvidenceSource::UserPrompt,
                "prompt",
                "api_key=super-secret",
            )],
            permits(),
            100,
            200,
            0.8,
        )
        .expect("contract signs");

        assert_eq!(contract.task_summary, "<redacted>");
        assert_eq!(contract.evidence[0].summary, "<redacted>");
        assert!(!format!("{contract:?}").contains("super-secret"));
    }

    #[test]
    fn rejects_invalid_contract_shape() {
        ScopeContract::signed("task", evidence(), permits(), 200, 100, 0.8)
            .expect_err("expiry must be after creation");
        ScopeContract::signed("task", evidence(), permits(), 100, 200, 1.1)
            .expect_err("confidence must be bounded");
        ScopeContract::signed("task", Vec::new(), permits(), 100, 200, 0.8)
            .expect_err("evidence is required");
    }
}
