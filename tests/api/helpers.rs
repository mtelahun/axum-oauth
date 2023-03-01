use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
#[allow(dead_code)]
pub fn spawn_blocking_with_tracing<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || current_span.in_scope(f))
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

        let response = self
            .api_client
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
        assert_is_redirect_to(&response, 303, "/oauth/", false);
    }

    pub async fn register_client(&self, params: &Value, client_type: ClientType) -> ClientResponse {
        // Arrange
        tracing::debug!("Test::POST /oauth/client (Register Client)");

        // Act
        let response = self
            .api_client
            .post(&format!("{}/oauth/client", self.app_address))
            .form(params)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            200,
            "client registration form processed successfully"
        );
        let res = response
            .json::<ClientResponse>()
            .await
            .expect("Failed to get response body");
        let client_secret = res
            .client_secret
            .clone()
            .map_or(String::new(), |secret| secret);
        assert!(
            !res.client_id.is_empty(),
            "The client_id field of the response is NOT empty"
        );
        match client_type {
            ClientType::Confidential => {
                assert!(
                    !client_secret.is_empty(),
                    "The client_secret field of the response is NOT empty"
                );
                assert_eq!(
                    client_secret.len(),
                    32,
                    "The client_secret field contains a response of the right length for nanoid output"
                );
            }
            ClientType::Public => {
                assert!(
                    client_secret.is_empty(),
                    "The client_secret field of the response IS empty"
                );
            }
        }

        res
    }

    pub async fn get_consent_prompt_confidential(
        &self,
        client: &ClientResponse,
        query: &Value,
    ) -> String {
        // Arrange
        tracing::debug!("Test::GET /oauth/authorize? (Get authorization)");
        let client_secret = client.client_secret.clone().unwrap();

        // Act
        let response = self
            .api_client
            .get(format!("{}/oauth/authorize", self.app_address))
            .basic_auth(client.client_id.clone(), Some(client_secret.clone()))
            .query(&query)
            .send()
            .await
            .expect("failed to get response from api client");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            200,
            "The authorization endpoint returns successfully"
        );
        let body = response
            .text()
            .await
            .expect("unable to decode response from dummy client");
        tracing::debug!("consent page:\n{}", body);
        assert!(
            body.contains("<h1>Authorize foo client</h1>"),
            "The authorization endpoint returned a consent page that shows the client name"
        );
        assert!(
            body.contains("<h4>foo client wants access to your <em>foo</em> account"),
            "The authorization endpoint returned a consent page that shows the target resource"
        );
        // let token: Token = serde_json::from_str(body.as_str()).unwrap();
        // for s in ["account:read", "account:write", "account:follow"] {
        //     assert!(token.scope.contains(s), "Token scope includes {}", s);
        // }

        body
    }

    pub async fn get_consent_prompt_public(&self, query: &Value) -> String {
        // Arrange
        tracing::debug!("Test::GET /oauth/authorize? (Get authorization)");

        // Act
        let response = self
            .api_client
            .get(format!("{}/oauth/authorize", self.app_address))
            .query(&query)
            .send()
            .await
            .expect("failed to get response from api client");

        // Assert
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .expect("unable to decode response from dummy client");
        tracing::debug!("consent page:\n{}", body);
        assert_eq!(
            status, 200,
            "The authorization endpoint returns successfully"
        );
        assert!(
            body.contains("<h1>Authorize foo client</h1>"),
            "The authorization endpoint returned a consent page that shows the client name"
        );
        assert!(
            body.contains("<h4>foo client wants access to your <em>foo</em> account"),
            "The authorization endpoint returned a consent page that shows the target resource"
        );
        // let token: Token = serde_json::from_str(body.as_str()).unwrap();
        // for s in ["account:read", "account:write", "account:follow"] {
        //     assert!(token.scope.contains(s), "Token scope includes {}", s);
        // }

        body
    }

    pub async fn owner_consent_allow(&self, body: &str) -> String {
        let re_action = Regex::new("formaction=\"(.*)\"").unwrap();
        let caps = re_action.captures(&body).unwrap();
        let allow_path = caps.get(1).map_or("/", |m| m.as_str());
        let allow_path = urlencoding::decode(allow_path).expect("failed to decode formaction");
        let allow_path = html_escape::decode_html_entities(&allow_path);
        let allow_uri = format!("{}/oauth/{}", self.app_address, allow_path);
        tracing::debug!("allow uri: {}", allow_uri);

        allow_uri
    }

    pub async fn capture_authorizer_redirect(
        &self,
        client: &ClientResponse,
        consent_response: &str,
        client_type: ClientType,
        csrf: &str,
    ) -> String {
        // Send response from owner consent to authorization endpoint
        let client_request = self.api_client.post(consent_response);
        let client_request = match client_type {
            ClientType::Confidential => client_request.basic_auth(
                client.client_id.clone(),
                Some(client.client_secret.clone().unwrap()),
            ),
            _ => client_request,
        };
        let response = client_request
            .send()
            .await
            .expect("failed to get response from api client");
        assert_is_redirect_to(&response, 302, "http://localhost:3001/endpoint?code=", true);

        // Get access token from authorizer redirect
        let location = response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .expect("failed to get redirect location");
        tracing::debug!("Client redirect: {}", location);
        let re_code = Regex::new("\\?code=(.*)\\&").unwrap();
        let caps = re_code.captures(&location).unwrap();
        let code = caps.get(1).map_or("X", |m| m.as_str());
        let code = urlencoding::decode(code).expect("failed to decode authorization code");
        tracing::debug!("Extracted code: {}", code);

        let re_code = Regex::new("\\&state=(.*)").unwrap();
        let caps = re_code.captures(&location).unwrap();
        let state = caps.get(1).map_or("X", |m| m.as_str());
        let state = urlencoding::decode(state).expect("failed to decode state");
        tracing::debug!("Extracted state: {}", state);

        assert_eq!(
            state, csrf,
            "Oauth state returned from authorization endpoint matches"
        );

        code.into_owned()
    }

    pub async fn exchange_auth_code_for_token(
        &self,
        client: &ClientResponse,
        client_type: ClientType,
        params: &Vec<(&str, &str)>,
    ) -> Token {
        // Act
        let client_request = self
            .api_client
            .post(format!("{}/oauth/token", self.app_address));
        let client_request = match client_type {
            ClientType::Confidential => client_request.basic_auth(
                client.client_id.clone(),
                Some(client.client_secret.clone().unwrap()),
            ),
            _ => client_request,
        };
        let response = client_request
            .form(params)
            .send()
            .await
            .expect("failed to get response from api client");

        // Assert
        let status = response.status().as_u16();
        let token = response.text().await.expect("failed to get response body");
        tracing::debug!("Token Response: {:?}", token);
        assert_eq!(status, 200, "Request for access token returns successfully");
        let token: Token = serde_json::from_str(token.as_str()).unwrap();
        assert_eq!(token.token_type, "bearer", "Token is a Bearer token");
        for s in ["account:read", "account:write", "account:follow"] {
            assert!(token.scope.contains(s), "Token scope includes {}", s);
        }
        assert!(
            !token.access_token.is_none(),
            "Access token contains a value"
        );
        assert!(
            !token.refresh_token.is_none(),
            "Refresh token contains a value"
        );
        assert!(
            token.error.is_none(),
            "Error value of token response is empty"
        );

        token
    }

    pub async fn refresh_token(
        &self,
        client: &ClientResponse,
        client_type: ClientType,
        params: &Vec<(&str, &str)>,
        str_old_token: String,
    ) -> Token {
        // Act
        let client_request = self
            .api_client
            .post(format!("{}/oauth/token", self.app_address));
        let client_request = match client_type {
            ClientType::Confidential => client_request.basic_auth(
                client.client_id.clone(),
                Some(client.client_secret.clone().unwrap()),
            ),
            _ => client_request,
        };
        let response = client_request
            .form(&params)
            .send()
            .await
            .expect("failed to get response from api client");

        // Assert
        let status = response.status().as_u16();
        let token = response.text().await.expect("failed to get response body");
        tracing::debug!("Token Response: {:?}", token);
        assert_eq!(
            status, 200,
            "Request for refresh token returns successfully"
        );
        let token: Token = serde_json::from_str(token.as_str()).unwrap();
        assert_eq!(token.token_type, "bearer", "Token is a Bearer token");
        for s in ["account:read", "account:write", "account:follow"] {
            assert!(token.scope.contains(s), "Token scope includes {}", s);
        }
        let new_token = token.access_token.clone().unwrap();
        assert!(
            !token.access_token.is_none() && new_token != str_old_token,
            "New access token is different from the previous token"
        );
        assert!(
            !token.refresh_token.is_none(),
            "Refresh token contains a value"
        );
        assert!(
            token.error.is_none(),
            "Error value of token response is empty"
        );

        token
    }

    pub async fn access_resource_success(&self, token: &str, substr: &str) {
        // Act
        let response = self
            .api_client
            .get(&format!("{}/oauth/whoami", &self.app_address))
            .bearer_auth(token)
            .send()
            .await
            .expect("request to client api failed");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            200,
            "Access to protected resource succeeded"
        );
        let body = response.text().await.unwrap();
        assert!(
            body.contains(substr),
            "Confirm access to protected resource"
        );
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

    // Launch app
    let (router, listener) = axum_oauth::build_service(Some("0.0.0.0:0".to_string()), 3000).await;
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(axum_oauth::serve(router, listener));

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

pub fn assert_is_redirect_to(
    response: &reqwest::Response,
    status_code: u16,
    location: &str,
    location_is_partial: bool,
) {
    assert_eq!(
        response.status().as_u16(),
        status_code,
        "received https status code: {} Redirect",
        status_code
    );
    if !location_is_partial {
        assert_eq!(
            response.headers().get("Location").unwrap(),
            location,
            "redirect location is: {}",
            location
        )
    } else {
        let loc_header = response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .expect("failed to convert header to str");

        assert!(
            loc_header.contains(location),
            "partial match to initial part of redirect location"
        )
    }
}

#[derive(Debug, Serialize)]
struct AuthorizationCode {
    code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub token_type: String,

    pub scope: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientType {
    Confidential,
    Public,
}
