use axum_macros::FromRef;
use oxide_auth::{
    endpoint::Scope,
    primitives::registrar::{Client, RegisteredUrl},
};
use secrecy::{ExposeSecret, Secret};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use self::{
    clientmap::ClientMap,
    resource::{client::ClientName, user::AuthUser},
};

use super::models::{ClientId, UserId};

pub mod clientmap;
pub mod resource;

#[derive(Clone, FromRef)]
pub struct Database {
    pub(crate) inner: Inner,
}

impl std::ops::Deref for Database {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

impl Database {
    pub fn new() -> Database {
        Database {
            inner: Inner {
                user_db: Arc::new(RwLock::new(HashMap::<UserId, UserRecord>::new())),
                client_db: Arc::new(RwLock::new(ClientMap::new())),
            },
        }
    }

    pub async fn register_user(&mut self, username: &str, password: Secret<String>) -> UserId {
        let id = UserId::new();
        let u = UserRecord::new(id, username, password.expose_secret());
        let mut map_lock = self.inner.user_db.write().await;
        map_lock.insert(id, u);

        id
    }

    pub async fn get_user_by_id(&self, user: &AuthUser) -> Result<UserRecord, StoreError> {
        let map_lock = self.inner.user_db.read().await;
        if self.contains_user_id(&user.user_id).await {
            let record = map_lock
                .get(&user.user_id)
                .ok_or(StoreError::DoesNotExist)?;
            return Ok(record.clone());
        }

        Err(StoreError::DoesNotExist)
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<UserRecord, StoreError> {
        let map_lock = self.inner.user_db.read().await;
        for v in (*map_lock).values() {
            if v.username == username {
                return Ok(v.clone());
            }
        }

        Err(StoreError::DoesNotExist)
    }

    pub async fn contains_user_id(&self, id: &UserId) -> bool {
        let map_lock = self.inner.user_db.read().await;
        map_lock.contains_key(id)
    }

    pub async fn contains_user_name(&self, username: &str) -> bool {
        match self.get_user_by_name(username).await {
            Ok(record) => record.username == username,
            Err(_) => false,
        }
    }

    // XXX - Doesn't really belong in a storage interface. It's just expeditious.
    pub async fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<bool, StoreError> {
        #[allow(unused_variables)]
        let map_lock = self.inner.user_db.read().await;
        let db = self.get_user_by_name(username).await?;
        let result = password == db.password.expose_secret();

        Ok(result)
    }

    pub async fn register_public_client(
        &mut self,
        client_name: &str,
        url: &str,
        default_scope: &str,
    ) -> Result<(String, Option<String>), StoreError> {
        let id = ClientId::new();
        let client = Client::public(
            id.as_str(),
            RegisteredUrl::Semantic(url.parse().unwrap()),
            default_scope.parse().unwrap(),
        );
        tracing::debug!("Registering public client: {:?}", client);

        let mut client_lock = self.inner.client_db.write().await;
        client_lock.register_client(id.as_str(), client_name, client);

        // There is currently no easy way to search ClientMap for a record. So, thisscopescopescope
        // function will allways succeed.
        Ok((id.to_string(), None))
    }

    pub async fn register_confidential_client(
        &mut self,
        client_name: &str,
        url: &str,
        default_scope: &str,
    ) -> Result<(String, Option<String>), StoreError> {
        let id = ClientId::new();
        let secret = nanoid::nanoid!(32);
        let client = Client::confidential(
            id.as_str(),
            RegisteredUrl::Semantic(url.parse().unwrap()),
            default_scope.parse().unwrap(),
            secret.as_bytes(),
        );
        tracing::debug!("Registering confidential client: {:?}", &client);
        let mut map_lock = self.inner.client_db.write().await;
        map_lock.register_client(id.as_str(), client_name, client);

        // There is currently no easy way to search ClientMap for a record. So, this
        // function will allways succeed.
        Ok((id.to_string(), Some(secret)))
    }

    pub async fn get_client_name(&self, client_id: ClientId) -> Result<ClientName, StoreError> {
        let map_lock = self.inner.client_db.read().await;
        let record = map_lock
            .clients
            .get(client_id.as_str())
            .ok_or(StoreError::InternalError)?;

        Ok(ClientName {
            inner: record.name.clone(),
        })
    }

    pub fn get_scope(&self, _user: &AuthUser, _client: ClientId) -> Option<Scope> {
        match "account::read".parse() {
            Ok(scope) => Some(scope),
            Err(_) => None,
        }
    }

    pub fn update_client_scope(&self, _client: ClientId, _scope: &Scope) {}
}

#[derive(Clone)]
pub struct Inner {
    pub(crate) user_db: Arc<RwLock<HashMap<UserId, UserRecord>>>,
    pub(crate) client_db: Arc<RwLock<ClientMap>>,
}

#[derive(Clone, Debug)]
pub struct UserRecord {
    id: UserId,
    username: String,
    password: Secret<String>,
    authorized_clients: Vec<ClientId>,
}

impl UserRecord {
    pub fn new(id: UserId, user: &str, password: &str) -> UserRecord {
        Self {
            id,
            username: user.to_owned(),
            password: Secret::from(password.to_owned()),
            authorized_clients: Vec::<ClientId>::new(),
        }
    }

    pub fn username(&self) -> Option<String> {
        if !self.username.is_empty() {
            return Some(self.username.clone());
        }

        None
    }

    pub fn id(&self) -> Option<UserId> {
        if !self.username.is_empty() {
            return Some(self.id);
        }

        None
    }

    pub fn add_authorized_client(&mut self, client_id: ClientId) {
        self.authorized_clients.push(client_id);
    }

    pub fn get_authorized_clients(&self) -> &Vec<ClientId> {
        &self.authorized_clients
    }
}

#[derive(Debug)]
pub enum StoreError {
    DoesNotExist,
    DuplicateRecord,
    InternalError,
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            StoreError::DoesNotExist => None,
            StoreError::DuplicateRecord => None,
            StoreError::InternalError => None,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StoreError::DoesNotExist => write!(f, "the record does not exist"),
            StoreError::DuplicateRecord => write!(f, "attempted to insert duplicate record"),
            StoreError::InternalError => write!(f, "an unexpected internal error occurred"),
        }
    }
}
