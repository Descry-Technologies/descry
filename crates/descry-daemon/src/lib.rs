use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

pub mod routes;

pub fn router() -> Router {
    Router::new()
        .route("/v1/pretooluse", post(routes::pretooluse))
        .route("/v1/status", get(routes::status))
        .route("/v1/approve", post(routes::approve))
}

pub async fn serve(addr: SocketAddr) -> io::Result<()> {
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "daemon bind address must be 127.0.0.1",
        ));
    }

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router()).await
}
