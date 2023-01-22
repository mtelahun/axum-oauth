use std::{sync::Arc, collections::HashMap};
use oxide_auth::primitives::registrar::{ClientMap, Client};
use secrecy::Secret;
use tokio::sync::RwLock;

pub mod resource;

#[derive(Clone)]
pub struct Database {
    pub (crate) inner: Inner,
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
            }
        }
    }

    pub async fn register_user(&mut self, user: UserRecord) {
        let mut map_lock = self.inner.user_db.write().await;
        map_lock.insert(user.username, user.password);
    }

    pub async fn contains_user(&self, username: &String) -> bool 
    {
        let map_lock = self.inner.user_db.read().await;
        map_lock.contains_key(username)
    }

    pub async fn register_client(&mut self, client: Client) {
        let mut map_lock = self.inner.client_db.write().await;
        map_lock.register_client(client);
    }
}

#[derive(Clone)]
pub struct Inner {
    pub (crate) user_db: Arc<RwLock<HashMap<String, Secret<String>>>>,
    pub (crate) client_db: Arc<RwLock<ClientMap>>,
}

#[derive(Clone, Debug)]
pub struct UserRecord {
    username: String,
    password: Secret<String>,
}

#[derive(Debug)]
pub enum StoreError {
    // Unable to find user in store
    DoesNotExist,
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            StoreError::DoesNotExist => None,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StoreError::DoesNotExist => write!(f, "the username does not exist"),
        }
    }
}
