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

                    let previous_scope =
                        db.get_scope(&user, client_id.parse::<ClientId>().unwrap());
                    if previous_scope.is_none() || previous_scope.unwrap() < scope {
                        db.update_client_scope(client_id.parse::<ClientId>().unwrap(), &scope);
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
