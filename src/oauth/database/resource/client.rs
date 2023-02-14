use oxide_auth::primitives::registrar::EncodedClient as Inner;
use serde::{Deserialize, Serialize};

use crate::oauth::models::{ClientId, UserId, InvalidLengthError, UserClientId};

#[derive(Serialize, Deserialize)]
pub struct EncodedClient {
    pub inner: Inner,
}

#[derive(Serialize, Deserialize)]
pub struct ClientName {
    pub inner: String,
}

// impl Resource for ClientName {
//     const NAME: &'static str = "client_name";

//     type Key = ClientQuery;
// }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AuthClient {
    pub user_id: UserId,
    pub id: ClientId,
}

impl AuthClient {
    pub fn to_user_client_id(&self) -> Result<UserClientId, InvalidLengthError> {
        let res = (self.user_id.to_string() + self.id.to_string().as_str())
            .parse::<UserClientId>()?;

        Ok(res)
    }
}

impl std::str::FromStr for AuthClient {
    type Err = InvalidLengthError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let user_id = src
            .get(0..UserId::LENGTH)
            .ok_or(InvalidLengthError {
                expected: UserId::LENGTH,
                actual: src.len(),
            })?
            .parse()?;

        let id = src[UserId::LENGTH..].parse()?;

        Ok(Self { user_id, id })
    }
}

// #[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
// pub struct ClientId(i64);

// impl Resource for EncodedClient {
//     const NAME: &'static str = "client";

//     type Key = ClientQuery;
// }

// impl Traverse<ClientName> for EncodedClient {
//     type Collection = Relation<ClientQuery, ClientName, ClientQuery, EncodedClient>;
// }
