extern crate reqwest;
extern crate serde;
extern crate serde_json;

use axum::http::StatusCode;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use std::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use self::reqwest::header;
use oxide_auth::endpoint::UniqueValue;

/// Send+Sync client implementation.
#[derive(Clone, Debug)]
pub struct Client {
    config: ClientConfig,
    state: Arc<RwLock<ClientState>>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
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

pub enum Error {
    /// The token was not valid for the access.
    AccessFailed,

    /// No token has been setup yet.
    NoToken,

    /// The bearer token could not be retrieved, bad request.
    AuthorizationFailed,

    /// The bearer token could not be retrieved, bad request.
    RefreshFailed,

    /// The answer should have been json but wasn't.
    Invalid(serde_json::Error),

    /// The answer did not contain a token.
    MissingToken,

    /// The token response indicates an error.
    Response(String),
}

#[derive(Clone, Debug, Default)]
struct ClientState {
    pub token: Option<String>,
    pub refresh: Option<String>,
    pub until: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub token_type: String,

    pub scope: String,

    #[serde(skip_serializing_if="Option::is_none")]
    pub access_token: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub refresh_token: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub expires_in: Option<i64>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub error: Option<String>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            state: Arc::new(RwLock::new(ClientState::default())),
        }
    }

    pub async fn authorize(&self, code: &str) -> Result<(), Error> {
        // Construct a request against http://localhost:8020/token, the access token endpoint
        let client = reqwest::Client::new();

        let mut state = self.state.write().await;

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &self.config.redirect_uri);
        let access_token_request =  match &self.config.client_secret{
            Some(client_secret) => client
                .post(&self.config.token_url)
                .form(&params)
                .basic_auth(&self.config.client_id, client_secret.get_unique())
                .build()
                .unwrap(),
            None =>{
                params.insert("client_id", &self.config.client_id);
                client
                .post(&self.config.token_url)
                .form(&params)
                .build().unwrap()
            }

        };

        let token_response = client
            .execute(access_token_request)
            .await
            .map_err(|_| Error::AuthorizationFailed)?;
        let token_map: Token = parse_token_response(token_response).await?;

        if let Some(err) = token_map.error {
            return Err(Error::Response(err));
        }

        if let Some(token) = token_map.access_token {
            state.token = Some(token);
            state.refresh = token_map.refresh_token;
            state.until = token_map.expires_in;
            return Ok(());
        }

        Err(Error::MissingToken)
    }

    pub async fn retrieve_protected_page(&self) -> Result<String, Error> {
        let client = reqwest::Client::new();

        let state = self.state.read().await;
        let token = match state.token {
            Some(ref token) => token,
            None => return Err(Error::NoToken),
        };

        // Request the page with the oauth token
        let page_request = client
            .get(&self.config.protected_url)
            .header(header::AUTHORIZATION, "Bearer ".to_string() + token)
            .build()
            .unwrap();

        let page_response = match client.execute(page_request).await {
            Ok(response) => response,
            Err(_) => return Err(Error::AccessFailed),
        };

        let protected_page = page_response.text().await.unwrap();
        Ok(protected_page)
    }

    pub async fn refresh(&self) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let mut state = self.state.write().await;
        let refresh = match state.refresh {
            Some(ref refresh) => refresh.clone(),
            None => return Err(Error::NoToken),
        };


        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", &refresh);

        let access_token_request = match &self.config.client_secret {
            Some(client_secret) => client
                .post(&self.config.refresh_url)
                .form(&params)
                .basic_auth(&self.config.client_id, client_secret.get_unique())
                .build().unwrap(),
            None => {
                params.insert("client_id", &self.config.client_id);
                client
                    .post(&self.config.refresh_url)
                    .form(&params)
                    .build().unwrap()
            }

        };
        let token_response = client
            .execute(access_token_request)
            .await
            .map_err(|_| Error::RefreshFailed)?;
        let token_map: Token = parse_token_response(token_response).await?;

        if token_map.error.is_some() || !token_map.access_token.is_some() {
            return Err(Error::MissingToken);
        }

        let token = token_map
            .access_token
            .unwrap();
        state.token = Some(token);
        state.refresh = token_map
            .refresh_token
            .or(state.refresh.take());
        state.until = token_map
            .expires_in;
        Ok(())
    }

    pub async fn as_html(&self) -> String {
        format!("{}", self.state.read().await)
    }
}

async fn parse_token_response(response: Response) -> Result<Token, serde_json::Error> {
    let token = response.text().await.unwrap();
    serde_json::from_str(&token)
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Invalid(err)
    }
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Token {<br>")?;
        write!(f, "&nbsp;token: {:?},<br>", self.token)?;
        write!(f, "&nbsp;refresh: {:?},<br>", self.refresh)?;
        write!(f, "&nbsp;expires_in: {:?},<br>", self.until)?;
        f.write_str("}")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AuthorizationFailed => f.write_str("Could not fetch bearer token"),
            Error::NoToken => f.write_str("No token with which to access protected page"),
            Error::AccessFailed => f.write_str("Access token failed to authorize for protected page"),
            Error::RefreshFailed => f.write_str("Could not refresh bearer token"),
            Error::Invalid(serde) => write!(f, "Bad json response: {}", serde),
            Error::MissingToken => write!(f, "No token nor error in server response"),
            Error::Response(err) => write!(f, "Server error while fetching token: {}", err),
        }
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let body = match self {
            _ => self.to_string(),
        };

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
