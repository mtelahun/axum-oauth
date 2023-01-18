use std::{collections::HashMap, sync::Arc};
use secrecy::Secret;

pub struct Database {
    inner: Arc<HashMap<String, Secret<String>>>,
}

impl Database {

    pub fn new() -> Database {
        Database {
            inner: Arc::new(HashMap::new()),
        }
    }

    pub fn insert(&self, username: &str, password: Secret<String>) {
        self.inner.insert(
            username.to_owned(), 
            password.to_owned(),
        );
    }

    pub fn fetch_password(&self, user: &str) -> Result<Secret<String>, StoreError> {
        match self.inner.get(user) {
            Some(rec) => Ok(rec.to_owned()),
            None => return Err(StoreError::DoesNotExist),
        }
    }
}

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
