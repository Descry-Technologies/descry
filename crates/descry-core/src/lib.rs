pub mod acp;
pub mod decision;
pub mod risk;
pub mod runtime;
pub mod scope;
pub mod signing_key;

pub use acp::{ActionContextPacket, InstructionProvenance, TrustLevel};
pub use decision::{Decision, DecisionOutput};
pub use risk::{Confidence, RiskScore};
pub use runtime::{
    append_runtime_session_event, classify_drift_signal, enrich_action_context, ActionClass,
    AssetGraphNode, AssetMatch, ClassifiedAction, DecisionInput, DriftSignal, HarnessEvent,
    RuntimeContextConfig, TaskEnvelope, TaskEnvelopeBuilder, TaskSource,
};
pub use scope::{
    EvidenceRef, EvidenceSource, ScopeContract, ScopeContractError, ScopePermit, ScopePermitKind,
    ScopeSignature,
};
