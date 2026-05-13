use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use descry_core::{ActionContextPacket, Confidence, Decision, DecisionOutput, RiskScore};
use serde_json::json;

pub async fn pretooluse(body: Bytes) -> Response {
    match serde_json::from_slice::<ActionContextPacket>(&body) {
        Ok(_acp) => Json(shim_decision()).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

pub fn shim_decision() -> DecisionOutput {
    DecisionOutput {
        decision: Decision::Allow,
        risk_score: RiskScore::try_from(0).expect("zero is a valid risk score"),
        confidence: Confidence::try_from(1.0).expect("one is a valid confidence"),
        reason: String::from("shim: no policy yet"),
        conditions: Vec::new(),
    }
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
        assert_eq!(json["risk_score"], 0);
        assert_eq!(json["confidence"], 1.0);
    }
}
