use axum_oauth::{build_service, serve};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod oauth;
pub mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (app, listener) = build_service(None, 3000).await;
    serve(app, listener).await;
}
