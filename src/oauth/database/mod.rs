use axum_macros::FromRef;
use oxide_auth::{
    endpoint::Scope,
    primitives::registrar::Client,
};
use secrecy::{ExposeSecret, Secret};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;

use self::{resource::{
    client::{AuthClient, ClientName},
    user::AuthUser,
}, clientmap::{ClientMap, WrappedClient}};

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

impl Database {
    pub fn new() -> Database {
        Database {
            inner: Inner {
                user_db: Arc::new(RwLock::new(HashMap::<String, Secret<String>>::new())),
                client_db: Arc::new(RwLock::new(ClientMap::new())),
            },
        }
    }

    pub async fn register_user(&mut self, user: UserRecord) {
        let mut map_lock = self.inner.user_db.write().await;
        map_lock.insert(user.username, user.password);
    }

    pub async fn get_user(&self, user: &AuthUser) -> Result<UserRecord, StoreError> {
        if self.contains_user(&user.username).await {
            return Ok(
                UserRecord {
                    username: user.username.to_owned(),
                    password: Secret::from("".to_string()),
                }
            )
        }

        Err(StoreError::DoesNotExist)
    }

    pub async fn contains_user(&self, username: &String) -> bool {
        let map_lock = self.inner.user_db.read().await;
        map_lock.contains_key(username)
    }

    // XXX - Doesn't really belong in a storage interface. It's just expeditious.
    pub async fn verify_password(
        &self,
        username: &String,
        password: &String,
    ) -> Result<bool, StoreError> {
        let map_lock = self.inner.user_db.read().await;
        if !map_lock.contains_key(username) {
            return Err(StoreError::DoesNotExist);
        }

        let db_password = map_lock.get(username).ok_or(StoreError::DoesNotExist)?;
        let result = password == db_password.expose_secret();

        Ok(result)
    }

    pub async fn register_client(
        &mut self,
        client_id: &str,
        client: WrappedClient,
        client_name: &str,
        username: &str,
    ) -> Result<(), StoreError> {
        let mut map_lock = self.inner.client_db.write().await;
        map_lock.register_wrapped_client(client);

        // There is currently no easy way to search ClientMap for a record. So, this
        // function will allways succeed. If the client is already in the ClientMap
        // its current value will be updated with the new value.
        Ok(())
    }

    pub async fn get_client_name(&self, client: &AuthClient, user: &AuthUser) -> Result<ClientName, StoreError> {
        Ok(ClientName { inner: "LocalClient".to_string() })
    }

    pub fn get_scope(&self, user: &AuthUser, client: &String) -> Option<Scope> {
        match "account::read".parse() {
            Ok(scope) => Some(scope),
            Err(_) => None,
        }
    }

    pub fn update_client_scope(&self, scope: &Scope) {
        ()
    }
}

#[derive(Clone)]
pub struct Inner {
    pub(crate) user_db: Arc<RwLock<HashMap<String, Secret<String>>>>,
    pub(crate) client_db: Arc<RwLock<ClientMap>>,
}

#[derive(Clone, Debug)]
pub struct UserRecord {
    username: String,
    password: Secret<String>,
}

impl UserRecord {
    pub fn new(user: &str, password: &str) -> UserRecord {
        Self {
            username: user.to_owned(),
            password: Secret::from(password.to_owned()),
        }
    }

    pub fn username(&self) -> Option<String> {
        if !self.username.is_empty() {
            return Some(self.username.clone());
        }

        None
    }
}

#[derive(Debug)]
pub enum StoreError {
    DoesNotExist,
    DuplicateRecord,
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            StoreError::DoesNotExist => None,
            StoreError::DuplicateRecord => None,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StoreError::DoesNotExist => write!(f, "the record does not exist"),
            StoreError::DuplicateRecord => write!(f, "attempted to insert duplicate record"),
        }
    }
}
