use crate::oauth::{
    database::{Database, resource::user::{AuthorizationQuery, Authorization}},
    routes::session::Session,
    solicitor::Solicitor,
    Consent,
    error::Error,
};
use axum::{
    extract::{FromRef, Query, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_macros::debug_handler;
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
    state
        .endpoint()
        .await
        .with_solicitor(FnSolicitor(
            move |_: &mut OAuthRequest, solicitation: Solicitation| {
                if let Consent::Allow = consent {
                    let PreGrant {
                        client_id, scope, ..
                    } = solicitation.pre_grant().clone();

                    let previous_scope = db.get_scope(&user, &client_id);
                    if previous_scope.is_none() || previous_scope.unwrap() < scope {
                        db.update_client_scope(&scope);
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
    let grant_type = request
        .body()
        .and_then(|x| x.unique_value("grant_type"))
        .unwrap_or_default();

    match &*grant_type {
        "refresh_token" => refresh(State(state), request).await,
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
