use std::str::FromStr;

use crate::oauth::{
    database::Database,
    error::{Result, Error},
    models::{ClientId, client::ClientQuery, UserId},
    templates,
};

use axum::{
    extract::{Form, FromRef, State},
    response::{IntoResponse, Json, Redirect},
    routing::get,
    Router,
};
use axum_sessions::extractors::ReadableSession;
use oxide_auth::primitives::registrar::{Client, RegisteredUrl};
use serde::{Deserialize, Serialize};
// use tf_database::{
//     primitives::Key,
//     query::{ClientQuery, UserQuery},
// };

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/", get(get_client).post(post_client))
}

async fn get_client() -> impl IntoResponse {
    templates::Client.into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClientType {
    Public,
    Confidential,
}

#[derive(Deserialize)]
struct ClientForm {
    name: String,
    redirect_uri: String,
    r#type: ClientType,
}

async fn post_client(
    State(mut db): State<Database>,
    session: ReadableSession,
    Form(client_form): Form<ClientForm>,
) -> Result<impl IntoResponse> {
    let user: String = match session.get("username") {
        Some(user) => user,
        _ => return Ok(Redirect::to("/oauth/signin").into_response()),
    };

    let client_name = client_form.name;

    let (client_id, client_secret) = match client_form.r#type {
        ClientType::Public => db.register_public_client(
                &client_name, 
                &client_form.redirect_uri, 
                "", 
                &user
            )
            .await
            .map_err(|e| Error::Database { source: (e) })?,

        ClientType::Confidential => db.register_confidential_client(
                &client_name, 
                &client_form.redirect_uri, 
                "", 
                &user
            )
            .await
            .map_err(|e| Error::Database { source: (e) })?,
    };

    #[derive(Serialize)]
    struct Response {
        client_id: String,
        client_secret: Option<String>,
    }

    Ok(Json(Response {
        client_id,
        client_secret,
    })
    .into_response())
}
