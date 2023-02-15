use serde::{Deserialize, Serialize};

use crate::oauth::models::{InvalidLengthError, UserId};

use super::client::AuthClient;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthUser {
    pub(crate) user_id: UserId,
    pub(crate) username: String,
}

impl std::fmt::Display for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.user_id, self.username)
    }
}

impl std::str::FromStr for AuthUser {
    type Err = InvalidLengthError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let user_id = src
            .get(0..UserId::LENGTH)
            .ok_or(InvalidLengthError {
                expected: UserId::LENGTH,
                actual: src.len(),
            })?
            .parse()?;

        let username = src[UserId::LENGTH + 1..].to_string();

        Ok(Self { user_id, username })
    }
}

pub struct AuthorizationQuery {
    pub user: AuthUser,
    pub client: AuthClient,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
