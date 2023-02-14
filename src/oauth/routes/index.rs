use super::session::Session;
use crate::{
    oauth::{
        database::{
            Database,
        },
        templates, error::Error,
    },
};
use axum::{
    extract::{FromRef, State},
    response::IntoResponse,
    routing::get,
    Router,
};

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/", get(index))
}

pub async fn index(Session { user }: Session, State(db): State<Database>) -> Result<impl IntoResponse, Error> {
    tracing::debug!("enter -> index()");
    let user_record = db.get_user_by_id(&user)
        .await
        .map_err(|e| Error::Database { source: e })?;
    tracing::debug!("user record: {:?}", user_record);
    let client_ids = user_record.get_authorized_clients();
    let mut clients = Vec::<String>::new();
    for id in client_ids {
        let client_name = db.get_client_name(*id)
            .await
            .map_err(|e| Error::Database { source: e })?;
        clients.push(client_name.inner);
    }

    Ok(templates::Index { clients: &clients }.into_response())
}
