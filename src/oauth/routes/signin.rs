use super::{Callback, LoginForm};
use crate::oauth::{
    database::{resource::user::AuthUser, Database},
    error::{Error, Result},
    templates::SignIn,
};

use axum::{
    extract::{Form, FromRef, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_sessions::extractors::WritableSession;

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    crate::oauth::state::State: FromRef<S>,
    Database: FromRef<S>,
{
    Router::new().route("/", get(get_signin).post(post_signin))
}

async fn get_signin(query: Option<Query<Callback<'_>>>) -> impl IntoResponse {
    let query = &query
        .as_ref()
        .and_then(|Query(x)| serde_urlencoded::to_string(x).ok())
        .unwrap_or_default();
    SignIn { query }.into_response()
}

async fn post_signin(
    State(db): State<Database>,
    query: Option<Query<Callback<'_>>>,
    mut session: WritableSession,
    Form(user_form): Form<LoginForm>,
) -> Result<impl IntoResponse> {
    let query = query.as_ref().map(|x| x.as_str());

    tracing::debug!("entered -> post_signin()");
    let user_record = db.get_user_by_name(&user_form.username).await;
    if user_record.is_err() {
        tracing::debug!("        user DOES NOT exist");
        return Ok((
            StatusCode::UNAUTHORIZED,
            SignIn {
                query: query.unwrap_or_default(),
            },
        )
            .into_response());
    }
    let user_record = user_record.unwrap();
    let authorized = db
        .verify_password(&user_form.username, &user_form.password)
        .await
        .map_err(|e| Error::Database { source: (e) })?;
    let _ = session.insert(
        "user",
        AuthUser {
            user_id: user_record.id().unwrap(),
            username: user_form.username,
        },
    );

    tracing::debug!("    checking authorization");
    if !authorized {
        tracing::debug!("        NOT authorized");
        Ok((
            StatusCode::UNAUTHORIZED,
            SignIn {
                query: query.unwrap_or_default(),
            },
        )
            .into_response())
    } else if let Some(query) = query {
        if !query.is_empty() {
            tracing::debug!("    redirect to callback: {}", query);
            Ok(Redirect::to(query).into_response())
        } else {
            tracing::debug!("    redirect to /oauth/");
            Ok(Redirect::to("/oauth/").into_response())
        }
    } else {
        tracing::debug!("    redirect to /oauth/");
        Ok(Redirect::to("/oauth/").into_response())
    }
}
