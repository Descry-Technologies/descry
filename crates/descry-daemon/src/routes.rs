use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use descry_core::{ActionContextPacket, RuntimeContextConfig};
use descry_engine::evaluate_action;
use descry_memory::{append_approval, Approval};
use serde::Deserialize;
use serde_json::json;

const DEFAULT_POLICY: &str = "policies/safe-defaults.yml";
const DEFAULT_PROJECT_POLICY: &str = ".descry/project.yml";
const DEFAULT_CONTEXT: &str = ".descry/context.md";

pub async fn pretooluse(body: Bytes) -> Response {
    match serde_json::from_slice::<ActionContextPacket>(&body) {
        Ok(acp) => match evaluate_pretooluse(acp) {
            Ok(decision) => Json(decision).into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error })),
            )
                .into_response(),
        },
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
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

pub async fn approve(body: Bytes) -> Response {
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
        Ok(()) => Json(json!({
            "status": "ok",
            "scope": req.scope,
            "expires_at": now + req.ttl_seconds,
            "approver": req.approver,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
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
    use tower::ServiceExt;

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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn approve_records_valid_approval() {
        let dir = tempfile::tempdir().expect("tempdir");
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
}
