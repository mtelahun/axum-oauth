use crate::oauth::{
    database::Database, error::Error, models::ClientId, routes::session::Session,
    solicitor::Solicitor, Consent,
};
use axum::{
    extract::{FromRef, Query, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use oxide_auth::{
    endpoint::{OwnerConsent, PreGrant, QueryParameter, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
    primitives::scope::Scope,
};
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};

pub fn routes<S>() -> Router<S>
where
    S: Send + Sync + 'static + Clone,
    crate::oauth::state::State: FromRef<S>,
    crate::oauth::database::Database: FromRef<S>,
{
    Router::new()
        .route("/authorize", get(get_authorize).post(post_authorize))
        .route("/refresh", get(refresh))
        .route("/token", post(token))
}

async fn get_authorize(
    State(state): State<crate::oauth::state::State>,
    State(db): State<Database>,
    Session { user }: Session,
    request: OAuthRequest,
) -> Result<impl IntoResponse, Error> {
    tracing::debug!("in get_authorize()");
    tracing::debug!("OAuth Request:\n{:?}", request);
    state
        .endpoint()
        .await
        .with_solicitor(Solicitor::new(db, user))
        .authorization_flow()
        .execute(request)
        .await
        .map(IntoResponse::into_response)
        .map_err(|e| Error::OAuth { source: e })
}

async fn post_authorize(
    State(state): State<super::super::state::State>,
    State(db): State<Database>,
    Query(consent): Query<Consent>,
    Session { user }: Session,
    request: OAuthRequest,
) -> Result<impl IntoResponse, Error> {
    tracing::debug!("in post_authorize()");
    tracing::debug!("request:\n{:?}", request);
    tracing::debug!("consent:\n{:?}", consent);

    state
        .endpoint()
        .await
        .with_solicitor(FnSolicitor(
            move |_: &mut OAuthRequest, solicitation: Solicitation| {
                if let Consent::Allow = consent {
                    let PreGrant {
                        client_id, scope, ..
                    } = solicitation.pre_grant().clone();

                    let current_scope = futures::executor::block_on(get_current_authorization(
                        &db,
                        &user.username,
                        &client_id,
                    ));
                    if current_scope.is_none() || current_scope.unwrap() < scope {
                        futures::executor::block_on(update_authorization(
                            &db,
                            &user.username,
                            &client_id,
                            scope,
                        ));
                    }

                    OwnerConsent::Authorized(user.to_string())
                } else {
                    OwnerConsent::Denied
                }
            },
        ))
        .authorization_flow()
        .execute(request)
        .await
        .map(IntoResponse::into_response)
        .map_err(|e| Error::OAuth { source: e })
}

async fn token(
    State(state): State<super::super::state::State>,
    request: OAuthRequest,
) -> Result<OAuthResponse, WebError> {
    tracing::debug!("Endpoint: token(), Request:\n{:?}", request);
    let grant_type = request
        .body()
        .and_then(|x| x.unique_value("grant_type"))
        .unwrap_or_default();
    tracing::debug!("Grant Type: {:?}", grant_type);

    match &*grant_type {
        "refresh_token" => refresh(State(state), request).await,
        // "client_credentials" => state
        //     .endpoint()
        //     .await
        //     .with_solicitor(FnSolicitor(
        //         move |_: &mut OAuthRequest, solicitation: Solicitation| {
        //             let PreGrant {
        //                 client_id, ..
        //             } = solicitation.pre_grant().clone();
        //             tracing::debug!("Client credentials consent OK: {}", client_id);
        //             OwnerConsent::Authorized(client_id.to_string())
        //         },
        //     ))
        //     .client_credentials_flow()
        //     .execute(request)
        //     .await,
        _ => {
            state
                .endpoint()
                .await
                .access_token_flow()
                .execute(request)
                .await
        }
    }
}

async fn refresh(
    State(state): State<super::super::state::State>,
    request: OAuthRequest,
) -> Result<OAuthResponse, WebError> {
    state.endpoint().await.refresh_flow().execute(request).await
}

async fn get_current_authorization(
    db: &Database,
    username: &str,
    client_str: &str,
) -> Option<Scope> {
    let user_record = db.get_user_by_name(username).await;
    let client_id = client_str.parse::<ClientId>();
    if user_record.is_err() || client_id.is_err() {
        return None;
    }
    let user_record = user_record.unwrap();
    let client_id = client_id.unwrap();

    db.get_scope(user_record.id().unwrap(), client_id).await
}

async fn update_authorization(db: &Database, username: &str, client_str: &str, new_scope: Scope) {
    let user_record = db.get_user_by_name(username).await;
    let client_id = client_str.parse::<ClientId>();
    if user_record.is_err() || client_id.is_err() {
        return;
    }
    let user_record = user_record.unwrap();
    let client_id = client_id.unwrap();
    let _ = db
        .update_client_scope(user_record.id().unwrap(), client_id, new_scope)
        .await;
}
