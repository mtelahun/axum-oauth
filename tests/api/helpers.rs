use once_cell::sync::Lazy;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};
use tokio::task::JoinHandle;
use tracing::subscriber::set_global_default;
use tracing::Subscriber;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Registry};

pub fn get_subscriber<Sink>(
    name: String,
    env_filter: String,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // Default to printing spans at info-level if RUST_LOG isn't set
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));

    let formatting_layer = BunyanFormattingLayer::new(name, sink);

    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    // Redirect all of `log`'s events to subscriber
    LogTracer::init().expect("Failed to set logger");
    set_global_default(subscriber).expect("Failed to set tracing subscriber");
}

// Just copied trait bounds and signature from `spawn_blocking`
pub fn spawn_blocking_with_tracing<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || current_span.in_scope(f))
}
/// Send+Sync client implementation.
// #[derive(Clone)]
// pub struct Client {
//     config: Config,
//     state: Arc<RwLock<State>>,
// }

#[derive(Clone)]
pub struct Config {
    /// The protected page.
    pub protected_url: String,

    /// Url to post to in order to get a token.
    pub token_url: String,

    /// Url to post to in order to refresh the token.
    pub refresh_url: String,

    /// The id that the client should use.
    pub client_id: String,

    /// The redirect_uri to use.
    pub redirect_uri: String,

    /// The client_secret to use.
    pub client_secret: Option<String>,
}

pub struct TestState {
    pub app_address: String,
    pub port: u16,
    pub api_client: reqwest::Client,
}

impl TestState {
    pub async fn signin(&self, username: &str, password: &str) {
        let form = serde_json::json!({
            "username": username,
            "password": password,
        });

        let response = self.api_client
            .post(&format!("{}/oauth/signin", &self.app_address))
            .form(&form)
            .send()
            .await
            .expect("request to server api failed");
        
        assert_eq!(
            response.status().as_u16(),
            303,
            "correct credentials result in 303 redirect to oauth root uri",
        );
        assert_is_redirect_to(&response, "/oauth/");
    }
}

// Ensure that the `tracing` stack is only initialized once
static TRACING: Lazy<()> = Lazy::new(|| {
    let default_filter_level = "test=debug,tower_http=debug".to_string();
    let subscriber_name = "test".to_string();
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

pub async fn spawn_app() -> TestState {
    // Initialize tracing stack
    Lazy::force(&TRACING);


    let (router, listener) =
        axum_oauth::build_service(Some("0.0.0.0:0".to_string()), 3000).await;
    let port = listener.local_addr().unwrap().port();

    let _ = tokio::spawn(axum_oauth::serve(router, listener));

    let reqwest_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    let res = TestState {
        app_address: format!("http://localhost:{}", port),
        port: port,
        api_client: reqwest_client,
    };
    tracing::debug!("The app was spawned at: {}", res.app_address);

    res
}

pub fn assert_is_redirect_to(response: &reqwest::Response, location: &str) {
    assert_eq!(
        response.status().as_u16(),
        303,
        "received https status code: 303 Redirect"
    );
    assert_eq!(
        response.headers().get("Location").unwrap(),
        location,
        "redirect location is: {}",
        location
    )
}
