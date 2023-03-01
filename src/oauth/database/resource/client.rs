use oxide_auth::primitives::registrar::EncodedClient as Inner;
use serde::{Deserialize, Serialize};

use crate::oauth::models::{ClientId, InvalidLengthError};

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
    pub id: ClientId,
}

impl std::str::FromStr for AuthClient {
    type Err = InvalidLengthError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let id = src.parse()?;

        Ok(Self { id })
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
