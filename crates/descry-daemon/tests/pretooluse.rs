use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use descry_daemon::{router, serve};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;

#[tokio::test]
async fn pretooluse_accepts_spec_example() {
    let response = router()
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
    let response = router()
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
async fn pretooluse_rejects_malformed_json() {
    let response = router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/pretooluse")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .expect("request builds"),
        )
        .await
        .expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let json: Value = serde_json::from_slice(&body).expect("response is json");

    assert!(json["error"]
        .as_str()
        .is_some_and(|error| !error.is_empty()));
}

#[tokio::test]
async fn daemon_rejects_non_localhost_bind_address() {
    let error = serve(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .expect_err("non-localhost bind fails");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("127.0.0.1"));
}
