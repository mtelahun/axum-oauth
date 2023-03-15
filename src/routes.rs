use std::str::FromStr;

use crate::oauth::{
    database::{resource::user::AuthUser, Database},
    error::Error,
    models::{ClientId, UserId},
    primitives::scopes::Grant,
    scopes::{Account, Read, Write},
};
use axum::{
    extract::{FromRef, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

pub fn routes<S>() -> Router<S>
where
    crate::oauth::state::State: FromRef<S>,
    S: Send + Sync + 'static + Clone,
    Database: FromRef<S>,
{
    Router::new().route("/user", get(user).post(update_account_name))
}

#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub id: ClientId,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: UserId,
    pub login: String,
    pub name: String,
    pub authorized_clients: Vec<ClientInfo>,
}

pub async fn user(
    State(db): State<Database>,
    grant: Grant<Read<Account>>,
) -> Result<Json<UserInfo>, Error> {
    tracing::debug!("enter -> user()");
    let u = grant.grant.owner_id;
    let user_record = db
        .get_user_by_id(&AuthUser::from_str(&u).unwrap())
        .await
        .map_err(|e| Error::Database { source: e })?;
    let authorized_clients = user_record.get_authorized_clients();
    let mut clients = Vec::<ClientInfo>::new();
    for cauth in authorized_clients {
        let client_name = db
            .get_client_name(cauth.client_id)
            .await
            .map_err(|e| Error::Database { source: e })?;
        clients.push(ClientInfo {
            id: cauth.client_id,
            name: client_name.inner,
        });
    }

    let user_info = UserInfo {
        id: user_record.id().unwrap(),
        login: user_record.username().unwrap(),
        name: user_record.given_name().unwrap(),
        authorized_clients: clients,
    };

    Ok(Json(user_info))
}

#[derive(Debug, Deserialize)]
pub struct ChangeResource {
    pub given_name: String,
}

#[derive(Debug, Default, Serialize)]
pub struct MsgReply {
    pub success: bool,
}

async fn update_account_name(
    State(mut db): State<Database>,
    grant: Grant<Write<Account>>,
    Json(form): Json<ChangeResource>,
) -> Result<Json<MsgReply>, Error> {
    tracing::debug!("enter -> update_account_name()");
    let u = grant.grant.owner_id;
    let success = db
        .update_given_name_by_id(&AuthUser::from_str(&u).unwrap(), &form.given_name)
        .await
        .map_err(|e| Error::Database { source: e })?;

    let res = MsgReply { success };

    Ok(Json(res))
}
