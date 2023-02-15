use crate::oauth::database::Database;
use oxide_auth::primitives::{
    registrar::{BoundClient, ClientUrl, PreGrant, RegistrarError},
    scope::Scope,
};
use oxide_auth_async::primitives::Registrar;

#[async_trait::async_trait]
impl Registrar for Database {
    async fn bound_redirect<'a>(
        &self,
        bound: ClientUrl<'a>,
    ) -> Result<BoundClient<'a>, RegistrarError> {
        let client_map_lock = self.inner.client_db.read().await;
        client_map_lock.bound_redirect(bound).await
    }

    async fn negotiate<'a>(
        &self,
        bound: BoundClient<'a>,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client_map_lock = self.inner.client_db.read().await;
        client_map_lock.negotiate(bound, scope).await
    }

    async fn check(
        &self,
        client_id: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<(), RegistrarError> {
        let client_map_lock = self.inner.client_db.read().await;
        client_map_lock.check(client_id, passphrase).await
    }
}
