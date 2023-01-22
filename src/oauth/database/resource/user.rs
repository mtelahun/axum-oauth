use serde::{Deserialize, Serialize};

use crate::oauth::models::{UserId, InvalidLengthError};

use super::client::AuthClient;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthUser {
    // pub user_id: UserId,
    pub username: String,
}

impl std::fmt::Display for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.username.fmt(f)
    }
}

impl std::str::FromStr for AuthUser {
    type Err = InvalidLengthError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let username = src.to_string();

        Ok(Self { username })
    }
}

pub struct AuthorizationQuery {
    pub user: AuthUser,
    pub client: AuthClient,
}

#[derive(Serialize, Deserialize)]
pub struct Authorization {
    pub scope: oxide_auth::primitives::scope::Scope,
}

// #[derive(Serialize, Deserialize)]
// pub struct User {
//     pub username: String,
//     pub password: String,
// }

// #[derive(Serialize, Deserialize)]
// pub struct Username;

// #[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
// pub struct UserId(i64);