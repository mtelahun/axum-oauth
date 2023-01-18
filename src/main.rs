use std::{
    fmt::Display,
    net::SocketAddr,
};

use async_session::{async_trait, MemoryStore};
use axum::{
    extract::{FromRef, FromRequestParts, State},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse},
    routing::{get},
    Json, RequestPartsExt, Router, TypedHeader,
};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use once_cell::sync::Lazy;
use oxide_auth::endpoint::{OwnerConsent, Solicitation, WebResponse, WebRequest, OwnerSolicitor};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::primitives::prelude::*;
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod oauth;
pub mod state;
use oauth::database::Database as AuthDB;
use state::AppState;

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

async fn index(claims: Claims) -> Result<String, AuthError> {
    Ok(format!("Hello World!\nYour data:\n {}", claims))
}

// async fn authorize(State(state): State<AppState>, req: OAuthRequest) -> Result<OAuthResponse, AuthError> {
    // Check if the user sent the credentials
    // if payload.client_id.is_empty() || payload.client_secret.is_empty() {
    //     return Err(AuthError::MissingCredentials);
    // }

    // // Here, check the user credentials from a database
    // if payload.client_id != "foo" || payload.client_secret != "bar" {
    //     return Err(AuthError::WrongCredentials);
    // }

    // let claims = Claims {
    //     sub: "b@b.com".to_owned(),
    //     company: "ACME".to_owned(),
    //     // Mandatory expiry time as UTC timestamp
    //     exp: 2000000000,
    // };

    // // Create the authorization token
    // let token = encode(&Header::default(), &claims, &KEYS.encoding)
    //     .map_err(|_| AuthError::TokenCreation)?;

    // println!("request:\n{:?}", req);
// }

// pub async fn authorize(
//     State(state): State<AppState>, req: OAuthRequest,
// ) -> Result<OAuthResponse, WebError> {
//     tracing::debug!("req = {:?}", req);
//     let endpoint = state.oauth
//         .endpoint();
//     tracing::debug!("    after endpoint");
//     let with_sol = endpoint.with_solicitor(FnSolicitor(consent_form));
//     tracing::debug!("    after with_solicitor");
//     let mut auth_flow = with_sol.authorization_flow();
//     tracing::debug!("    after auth_flow");
//     let res = auth_flow.execute(req)?;
//     tracing::debug!("exiting authorize()");
//     Ok(res)
// }

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_oauth=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let auth_db = AuthDB::new();
    auth_db.insert("janedoe", Secret::from("secret".to_string()));
    let state = oauth::state::State::new();
    let store = MemoryStore::new();
    let state = AppState {
        store,
        state: state,
    };

    let app = Router::new()
        .route("/", get(index))
        // .route("/authorize", get(authorize))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.company)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, Serialize)]
struct AuthBody {
    auth: String,
    //query: NormalizedParameter,
    //body: String,
}

// impl AuthBody {
//     fn new(access_token: String) -> Self {
//         Self {
//             access_token,
//             token_type: "Bearer".to_string(),
//         }
//     }
// }

#[derive(Debug, Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    Unexecpected(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid token"),
            AuthError::Unexecpected(_) => (StatusCode::INTERNAL_SERVER_ERROR, "unknown internal error"),
        };
        let body = Json(serde_json::json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl From<WebError> for AuthError {
    fn from(err: WebError) -> Self {
        match err {
            WebError::Endpoint(_) => AuthError::Unexecpected("internal authorization error".to_string()),
            WebError::Header(h) => AuthError::Unexecpected(h.to_string()),
            WebError::Encoding => AuthError::MissingCredentials,
            WebError::Form => AuthError::MissingCredentials,
            WebError::Query => AuthError::MissingCredentials,
            WebError::Body => AuthError::MissingCredentials,
            WebError::Authorization => AuthError::InvalidToken,
            WebError::InternalError(opt) => match opt {
                Some(e) => AuthError::Unexecpected(e),
                None => AuthError::Unexecpected("unknown authentication error".to_string())
            },
        }
    }
}

fn consent_form(
    _: &mut OAuthRequest, solicitation: Solicitation,
) -> OwnerConsent<OAuthResponse> {
    let r = OAuthResponse::default()
            .body(
                consent_page_html(
                    "/authorize",
                    solicitation,
                ).as_str()
            )
            .content_type("text/html")
            .unwrap();
    OwnerConsent::InProgress(r)
}

// fn consent_decision(allowed: bool, _: Solicitation) -> OwnerConsent<impl WebResponse> {
//     if allowed {
//         OwnerConsent::Authorized("dummy user".into())
//     } else {
//         OwnerConsent::Denied
//     }
// }

pub fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
    tracing::debug!("enter consent_page_html()");
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
</form>
</html>"
        };
    }

    tracing::debug!("    solicitation.pre_grant()");
    let grant = solicitation.pre_grant();
    tracing::debug!("    solicitation.state()");
    let state = solicitation.state();

    let mut extra = vec![
        ("response_type", "code"),
        ("client_id", grant.client_id.as_str()),
        ("redirect_uri", grant.redirect_uri.as_str()),
    ];

    if let Some(state) = state {
        extra.push(("state", state));
    }
    
    tracing::debug!("    displaying template...");
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        serde_urlencoded::to_string(extra).unwrap(),
        &route,
    )
}
