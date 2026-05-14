use std::path::Path;

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use descry_core::ActionContextPacket;
use descry_engine::{build_decision_input, evaluate, EvaluationRuntime};
use descry_policy::{Policy, ProjectPolicy};
use serde_json::json;

const BUILT_IN_SAFE_DEFAULTS: &str = include_str!("../../../policies/safe-defaults.yml");
const DEFAULT_PROJECT_POLICY: &str = ".descry/project.yml";
const DEFAULT_APPROVALS: &str = ".descry/memory/approvals.jsonl";
const DEFAULT_BEHAVIOR: &str = ".descry/memory/behavior.json";

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
    let policy = Policy::load_yaml(BUILT_IN_SAFE_DEFAULTS)
        .map_err(|error| format!("failed to load built-in policy: {error}"))?;
    let project_config = load_project_policy(Path::new(DEFAULT_PROJECT_POLICY))?;
    let decision_input = build_decision_input(acp);

    Ok(evaluate(
        decision_input,
        EvaluationRuntime {
            policy: &policy,
            project_config: &project_config,
            approvals_path: Path::new(DEFAULT_APPROVALS),
            behavior_path: Path::new(DEFAULT_BEHAVIOR),
        },
    ))
}

fn load_project_policy(path: &Path) -> Result<ProjectPolicy, String> {
    if !path.exists() {
        return Ok(ProjectPolicy::default());
    }

    let body = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read project policy {}: {error}", path.display()))?;
    ProjectPolicy::load_yaml(&body)
        .map_err(|error| format!("failed to load project policy {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::pretooluse;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
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
