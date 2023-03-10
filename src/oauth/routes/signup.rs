use super::{Callback, UserForm};
use crate::oauth::{database::Database, error::Result, templates::SignUp};
use axum::{
    extract::{Form, FromRef, Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use secrecy::Secret;

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/", get(get_signup).post(post_signup))
}

async fn get_signup(query: Option<Query<Callback<'_>>>) -> impl IntoResponse {
    let query = &query
        .as_ref()
        .map(|Query(x)| serde_urlencoded::to_string(x).unwrap())
        .unwrap_or_default();
    SignUp { query }.into_response()
}

async fn post_signup(
    State(mut db): State<Database>,
    _query: Option<Query<Callback<'_>>>,
    Form(user): Form<UserForm>,
) -> Result<impl IntoResponse> {
    if db.contains_user_name(&user.username).await {
        return Ok(Redirect::to("signin"));
    }

    db.register_user(&user.username, Secret::from(user.password))
        .await;

    Ok(Redirect::to("/"))
}
