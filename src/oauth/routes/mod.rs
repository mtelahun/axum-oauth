use crate::oauth::database::Database;
use axum::{extract::FromRef, Router};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use tower_sessions::{
    cookie::{Key, SameSite},
    MemoryStore, SessionManagerLayer,
};

mod session {
    use crate::oauth::database::resource::user::AuthUser;

    use super::Callback;
    use axum::{extract::FromRequestParts, http::request::Parts, response::Redirect};
    use tower_sessions::Session as TowerSession;

    pub struct Session {
        pub user: AuthUser,
    }

    impl<S> FromRequestParts<S> for Session
    where
        S: Send + Sync + 'static,
    {
        type Rejection = Redirect;

        async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
            tracing::debug!("Middleware: Session: parts: {:?}", parts);
            let session = match TowerSession::from_request_parts(parts, state).await {
                Ok(session) => session.get::<AuthUser>("user").await.ok().flatten(),
                Err(_) => None,
            };

            if let Some(user) = session {
                Ok(Self { user })
            } else {
                let path_and_query = parts
                    .uri
                    .path_and_query()
                    .map(|x| x.as_str())
                    .map(|x| x.trim_start_matches('/'))
                    .unwrap_or_default();
                let callback = Callback::from_str(path_and_query);

                let uri = format!(
                    "/oauth/signin?{}",
                    serde_urlencoded::to_string(callback).unwrap()
                );

                Err(Redirect::to(&uri))
            }
        }
    }
}

pub fn routes<S>() -> Router<S>
where
    crate::oauth::state::State: FromRef<S>,
    Database: FromRef<S>,
    S: Send + Sync + 'static + Clone,
{
    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_name("axum_oauth")
        .with_secure(true)
        .with_path("/oauth/")
        .with_same_site(SameSite::Lax)
        .with_signed(Key::generate());

    Router::new()
        .merge(oauth::routes())
        .nest("/client", client::routes())
        .nest("/signin", signin::routes())
        .nest("/signout", signout::routes().with_state(()))
        .nest("/signup", signup::routes())
        .layer(session_layer)
}

mod client;
mod oauth;
mod signin;
mod signout;
mod signup;

#[derive(Default, Serialize, Deserialize)]
pub struct Callback<'a> {
    callback: Cow<'a, str>,
}

impl<'a> Callback<'a> {
    fn as_str(&self) -> &str {
        self.callback.as_ref()
    }

    fn from_str(callback: &'a str) -> Self {
        Self {
            callback: Cow::Borrowed(callback),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Clone)]
pub struct SignUpForm {
    pub username: String,
    pub password: String,
    pub given_name: String,
}
