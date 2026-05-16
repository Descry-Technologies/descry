use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use descry_core::{ActionContextPacket, RuntimeContextConfig};
use descry_engine::evaluate_action;
use descry_memory::{append_approval, Approval};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

const DEFAULT_POLICY: &str = "policies/safe-defaults.yml";
const DEFAULT_PROJECT_POLICY: &str = ".descry/project.yml";
const DEFAULT_CONTEXT: &str = ".descry/context.md";

// Prometheus-style counters — monotonic, process-lifetime scope.
static COUNTER_ALLOW: AtomicU64 = AtomicU64::new(0);
static COUNTER_ALLOW_WITH_LOG: AtomicU64 = AtomicU64::new(0);
static COUNTER_ASK: AtomicU64 = AtomicU64::new(0);
static COUNTER_REQUIRE_APPROVAL: AtomicU64 = AtomicU64::new(0);
static COUNTER_BLOCK: AtomicU64 = AtomicU64::new(0);
static COUNTER_ERRORS: AtomicU64 = AtomicU64::new(0);

pub async fn pretooluse(body: Bytes) -> Response {
    match serde_json::from_slice::<ActionContextPacket>(&body) {
        Ok(acp) => match evaluate_pretooluse(acp) {
            Ok(decision) => {
                let label = decision.decision.as_str();
                increment_decision_counter(label);
                info!(decision = label, risk = decision.risk_score.0, "pretooluse evaluated");
                Json(decision).into_response()
            }
            Err(error) => {
                COUNTER_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(%error, "pretooluse evaluation error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": error })),
                )
                    .into_response()
            }
        },
        Err(error) => {
            COUNTER_ERRORS.fetch_add(1, Ordering::Relaxed);
            warn!(%error, "pretooluse parse error");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error.to_string() })),
            )
                .into_response()
        }
    }
}

fn evaluate_pretooluse(acp: ActionContextPacket) -> Result<descry_core::DecisionOutput, String> {
    let project_root = std::env::current_dir()
        .map_err(|error| format!("failed to resolve daemon project root: {error}"))?;
    let state_dir = std::env::var_os("DESCRY_DAEMON_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_dir);
    let config = RuntimeContextConfig {
        project_root,
        context_path: PathBuf::from(DEFAULT_CONTEXT),
        project_index_path: state_dir.join("project-index.json"),
        approvals_path: state_dir.join("approvals.jsonl"),
        behavior_path: state_dir.join("behavior.json"),
        state_dir,
        project_policy_path: PathBuf::from(DEFAULT_PROJECT_POLICY),
        policy_path: workspace_root().join(DEFAULT_POLICY),
        audit_path: None,
        repo_id_hash: String::from("descry-daemon"),
        legacy_asset_policy_path: None,
    };
    evaluate_action(acp, &config, None, false).map(|evaluated| evaluated.decision)
}

fn default_state_dir() -> PathBuf {
    // Prefer a persistent, user-scoped directory so approvals survive daemon restarts.
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home).join(".descry").join("daemon");
    }
    // Fallback for environments without $HOME (CI containers, unusual setups).
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "descry-daemon-state-{}-{nonce}",
        std::process::id()
    ))
}

pub async fn status() -> Response {
    let version = env!("CARGO_PKG_VERSION");
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| String::from("<unknown>"));
    let state_dir = std::env::var_os("DESCRY_DAEMON_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_dir);
    let approvals_path = state_dir.join("approvals.jsonl");
    let live_count = descry_memory::live_approvals(
        &approvals_path,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
    )
    .map(|v| v.len())
    .unwrap_or(0);
    Json(json!({
        "version": version,
        "cwd": cwd,
        "live_approvals": live_count,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    scope: String,
    ttl_seconds: u64,
    approver: String,
}

pub async fn approve(headers: HeaderMap, body: Bytes) -> Response {
    if !is_authorized(&headers) {
        warn!("approve rejected: missing or invalid bearer token");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid Authorization: Bearer token" })),
        )
            .into_response();
    }

    let req: ApproveRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let state_dir = std::env::var_os("DESCRY_DAEMON_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_state_dir);
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to create state dir: {e}") })),
        )
            .into_response();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let approval = Approval {
        scope: req.scope.clone(),
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now + req.ttl_seconds,
        approver: req.approver.clone(),
    };
    let approvals_path = state_dir.join("approvals.jsonl");
    match append_approval(&approvals_path, &approval) {
        Ok(()) => {
            info!(scope = %req.scope, approver = %req.approver, ttl = req.ttl_seconds, "approval recorded");
            Json(json!({
                "status": "ok",
                "scope": req.scope,
                "expires_at": now + req.ttl_seconds,
                "approver": req.approver,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn metrics() -> Response {
    let body = format!(
        "# HELP descry_decisions_total Total firewall decisions by outcome\n\
         # TYPE descry_decisions_total counter\n\
         descry_decisions_total{{outcome=\"allow\"}} {}\n\
         descry_decisions_total{{outcome=\"allow_with_log\"}} {}\n\
         descry_decisions_total{{outcome=\"ask\"}} {}\n\
         descry_decisions_total{{outcome=\"require_approval\"}} {}\n\
         descry_decisions_total{{outcome=\"block\"}} {}\n\
         # HELP descry_errors_total Total daemon errors (parse + evaluation)\n\
         # TYPE descry_errors_total counter\n\
         descry_errors_total {}\n",
        COUNTER_ALLOW.load(Ordering::Relaxed),
        COUNTER_ALLOW_WITH_LOG.load(Ordering::Relaxed),
        COUNTER_ASK.load(Ordering::Relaxed),
        COUNTER_REQUIRE_APPROVAL.load(Ordering::Relaxed),
        COUNTER_BLOCK.load(Ordering::Relaxed),
        COUNTER_ERRORS.load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

/// Verifies a bearer token against the daemon token file at `~/.descry/daemon.token`.
/// If the token file does not exist, authentication is not enforced (backwards compat
/// with single-user dev setups that have not run `descry daemon init`).
fn is_authorized(headers: &HeaderMap) -> bool {
    let token_path = token_file_path();
    let Ok(expected) = fs::read_to_string(&token_path) else {
        // No token file → open mode; log a startup warning instead of blocking.
        return true;
    };
    let expected = expected.trim();
    if expected.is_empty() {
        return true;
    }

    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| constant_time_eq(t, expected))
}

/// Constant-time string comparison to prevent timing attacks on token comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn token_file_path() -> PathBuf {
    if let Some(explicit) = std::env::var_os("DESCRY_DAEMON_TOKEN_FILE") {
        return PathBuf::from(explicit);
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home).join(".descry").join("daemon.token")
    } else {
        PathBuf::from(".descry").join("daemon.token")
    }
}

fn increment_decision_counter(label: &str) {
    match label {
        "allow" => COUNTER_ALLOW.fetch_add(1, Ordering::Relaxed),
        "allow_with_log" => COUNTER_ALLOW_WITH_LOG.fetch_add(1, Ordering::Relaxed),
        "ask" => COUNTER_ASK.fetch_add(1, Ordering::Relaxed),
        "require_approval" => COUNTER_REQUIRE_APPROVAL.fetch_add(1, Ordering::Relaxed),
        "block" => COUNTER_BLOCK.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon crate has workspace parent")
        .parent()
        .expect("crates dir has workspace parent")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{approve, pretooluse, status};
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use serde_json::Value;
    use std::sync::{Mutex, OnceLock};
    use tower::ServiceExt;

    // Serializes all tests that mutate process-wide env vars.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn pretooluse_returns_allow_for_valid_acp() {
        let app = Router::new().route("/v1/pretooluse", post(pretooluse));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pretooluse")
                    .header("content-type", "application/json")
                    .body(Body::from(include_str!(
                        "../../descry-core/tests/fixtures/spec_example.json"
                    )))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let json: Value = serde_json::from_slice(&body).expect("response is json");

        assert_eq!(json["decision"], "allow");
    }

    #[tokio::test]
    async fn status_returns_version_and_cwd() {
        let app = Router::new().route("/v1/status", get(status));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/status")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let json: Value = serde_json::from_slice(&body).expect("response is json");

        assert!(json["version"].is_string());
        assert!(json["cwd"].is_string());
        assert!(json["live_approvals"].is_number());
    }

    #[tokio::test]
    async fn approve_rejects_missing_fields() {
        let _guard = env_lock().lock().unwrap();
        // Point to a non-existent token file path so auth is disabled for this test.
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("DESCRY_DAEMON_TOKEN_FILE", dir.path().join("no-token"));

        let app = Router::new().route("/v1/approve", post(approve));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"scope":"path:**"}"#))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        // Without a token file, auth passes; the missing fields should produce 400.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        std::env::remove_var("DESCRY_DAEMON_TOKEN_FILE");
    }

    #[tokio::test]
    async fn approve_records_valid_approval() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        // Point to a non-existent token file so auth is disabled.
        std::env::set_var("DESCRY_DAEMON_TOKEN_FILE", dir.path().join("no-token"));
        std::env::set_var("DESCRY_DAEMON_STATE_DIR", dir.path());

        let app = Router::new().route("/v1/approve", post(approve));
        let body = serde_json::json!({
            "scope": "path:src/**",
            "ttl_seconds": 3600,
            "approver": "alice"
        })
        .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let json: Value = serde_json::from_slice(&bytes).expect("response is json");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["scope"], "path:src/**");
        assert_eq!(json["approver"], "alice");
        assert!(json["expires_at"].as_u64().unwrap() > 0);

        std::env::remove_var("DESCRY_DAEMON_TOKEN_FILE");
        std::env::remove_var("DESCRY_DAEMON_STATE_DIR");
    }

    #[tokio::test]
    async fn pretooluse_blocks_rm_rf_home() {
        let app = Router::new().route("/v1/pretooluse", post(pretooluse));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/pretooluse")
                    .header("content-type", "application/json")
                    .body(Body::from(include_str!(
                        "../../../fixtures/rm-rf-home.json"
                    )))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        let json: Value = serde_json::from_slice(&body).expect("response is json");

        assert_eq!(json["decision"], "block");
    }

    #[tokio::test]
    async fn approve_rejects_invalid_token() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let token_file = dir.path().join("daemon.token");
        std::fs::write(&token_file, "correct-token\n").expect("write token");

        std::env::set_var("DESCRY_DAEMON_TOKEN_FILE", &token_file);
        std::env::set_var("DESCRY_DAEMON_STATE_DIR", dir.path());

        let app = Router::new().route("/v1/approve", post(approve));
        let body = serde_json::json!({
            "scope": "path:src/**",
            "ttl_seconds": 3600,
            "approver": "attacker"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approve")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        std::env::remove_var("DESCRY_DAEMON_TOKEN_FILE");
        std::env::remove_var("DESCRY_DAEMON_STATE_DIR");
    }

    #[tokio::test]
    async fn approve_accepts_correct_token() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let token_file = dir.path().join("daemon.token");
        std::fs::write(&token_file, "correct-token\n").expect("write token");

        std::env::set_var("DESCRY_DAEMON_TOKEN_FILE", &token_file);
        std::env::set_var("DESCRY_DAEMON_STATE_DIR", dir.path());

        let app = Router::new().route("/v1/approve", post(approve));
        let body = serde_json::json!({
            "scope": "path:src/**",
            "ttl_seconds": 3600,
            "approver": "alice"
        })
        .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/approve")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer correct-token")
                    .body(Body::from(body))
                    .expect("request builds"),
            )
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::OK);

        std::env::remove_var("DESCRY_DAEMON_TOKEN_FILE");
        std::env::remove_var("DESCRY_DAEMON_STATE_DIR");
    }
}
