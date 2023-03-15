use crate::oauth::{
    database::Database,
    error::{Error, Result},
};

use axum::{
    extract::{Form, FromRef, State},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/", post(post_client))
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
    Form(client_form): Form<ClientForm>,
) -> Result<impl IntoResponse> {
    tracing::debug!("POST Handler: post_client()");

    let client_name = client_form.name;

    let (client_id, client_secret) = match client_form.r#type {
        ClientType::Public => db
            .register_public_client(&client_name, &client_form.redirect_uri, "")
            .await
            .map_err(|e| Error::Database { source: (e) })?,

        ClientType::Confidential => db
            .register_confidential_client(&client_name, &client_form.redirect_uri, "")
            .await
            .map_err(|e| Error::Database { source: (e) })?,
    };

    #[derive(Serialize)]
    struct Response {
        client_id: String,
        client_secret: Option<String>,
    }

    tracing::debug!(
        "POST Handler: post_client(): return (id, secret): ({:?},{:?})",
        client_id,
        client_secret
    );
    Ok(Json(Response {
        client_id,
        client_secret,
    })
    .into_response())
}
