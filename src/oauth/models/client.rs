use serde::{Deserialize, Serialize};

use super::{ClientId, UserId};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ClientQuery {
    pub user_id: UserId,
    pub id: ClientId,
}

impl std::fmt::Display for ClientQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.user_id, self.id)
    }
}
