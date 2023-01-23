use super::{Callback, UserForm};
use crate::oauth::{
    database::Database,
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
    Form(user_form): Form<UserForm>,
) -> Result<impl IntoResponse> {
    let query = query.as_ref().map(|x| x.as_str());

    let authorized = db.verify_password(&user_form.username, &user_form.password)
        .await
        .map_err(|e| Error::Database { source: (e) })?;
    session.insert("user", user_form.username);

    if !authorized {
        Ok((
            StatusCode::UNAUTHORIZED,
            SignIn {
                query: query.unwrap_or_default(),
            },
        )
            .into_response())
    } else if let Some(query) = query {
        Ok(Redirect::to(query).into_response())
    } else {
        Ok(Redirect::to("/oauth/").into_response())
    }
}
