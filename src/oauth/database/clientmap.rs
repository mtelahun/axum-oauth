use std::collections::HashMap;

use once_cell::sync::Lazy;
use oxide_auth::primitives::registrar::{EncodedClient, PasswordPolicy, Client, Argon2};


static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(Argon2::default);

#[derive(Default)]
pub struct ClientMap {
    clients: HashMap<String, EncodedClient>,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

impl ClientMap {
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap::default()
    }

    /// Insert or update the client record.
    pub fn register_wrapped_client(&mut self, client: WrappedClient) {
        let password_policy = Self::current_policy(&self.password_policy);
        self.clients
            .insert(client.client_id, client.inner.encode(password_policy));
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy<'a>(policy: &'a Option<Box<dyn PasswordPolicy>>) -> &'a dyn PasswordPolicy {
        policy
            .as_ref()
            .map(|boxed| &**boxed)
            .unwrap_or(&*DEFAULT_PASSWORD_POLICY)
    }
}

impl Extend<WrappedClient> for ClientMap {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = WrappedClient>,
    {
        iter.into_iter().for_each(|client| self.register_wrapped_client(client))
    }
}

impl FromIterator<WrappedClient> for ClientMap {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = WrappedClient>,
    {
        let mut into = ClientMap::new();
        into.extend(iter);
        into
    }
}

pub struct WrappedClient {
    pub client_id: String,
    pub inner: Client,
}
