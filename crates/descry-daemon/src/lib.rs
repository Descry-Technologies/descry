use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub mod routes;

pub fn router() -> Router {
    Router::new()
        .route("/v1/pretooluse", post(routes::pretooluse))
        .route("/v1/status", get(routes::status))
        .route("/v1/approve", post(routes::approve))
        .route("/v1/metrics", get(routes::metrics))
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_env("DESCRY_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

pub async fn serve(addr: SocketAddr) -> io::Result<()> {
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "daemon bind address must be 127.0.0.1",
        ));
    }

    info!(version = env!("CARGO_PKG_VERSION"), %addr, "descry daemon starting");
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "descry daemon listening");
    axum::serve(listener, router()).await
}
