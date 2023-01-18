use oxide_auth::{
    frontends::simple::endpoint::Vacant,
    primitives::{authorizer::AuthMap, generator::RandomGenerator, issuer::TokenMap, registrar::{ClientMap, Client}},
};
use oxide_auth_async::primitives;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::oauth::database::Database;
use super::endpoint::{extension::Empty, Endpoint};


#[derive(Clone, axum_macros::FromRef)]
pub struct State {
    registrar: Database,
    authorizer: Arc<Mutex<AuthMap<RandomGenerator>>>,
    issuer: Arc<Mutex<TokenMap<RandomGenerator>>>,
}

impl State {
    pub fn new(registrar: Database) -> Self {
        State {
            registrar,
            authorizer: Arc::new(Mutex::new(AuthMap::new(RandomGenerator::new(16)))),
            issuer: Arc::new(Mutex::new(TokenMap::new(RandomGenerator::new(16)))),
        }
    }

    pub async fn endpoint(
        &self,
    ) -> Endpoint<'_, impl primitives::Registrar, Empty, Vacant, Vacant> {
        Endpoint {
            registrar: &self.registrar,
            authorizer: self.authorizer.lock().await.into(),
            issuer: self.issuer.lock().await.into(),
            extension: Empty,
            solicitor: Vacant,
            scopes: Vacant,
        }
    }
}

// impl fmt::Debug for OAuthState {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let registrar = self.registrar.lock().unwrap();
//         let authorizer = self.authorizer.lock().unwrap();
//         let issuer = self.issuer.lock().unwrap();
//         f.debug_struct("OAuthState")
//             .field("registrar", &registrar)
//             .field("authorizer", &authorizer)
//             .field("issuer", &issuer)
//             .finish()
//     }
// }