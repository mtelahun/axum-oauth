use std::{collections::HashMap, borrow::Cow};

use once_cell::sync::Lazy;
use oxide_auth::{primitives::registrar::{Argon2, Client, EncodedClient, PasswordPolicy, BoundClient, RegistrarError, ClientUrl, RegisteredClient}, endpoint::{Scope, PreGrant, Registrar}};

use crate::oauth::models::UserId;

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(Argon2::default);

#[derive(Default)]
pub struct ClientMap {
    pub (crate) clients: HashMap<String, ClientRecord>,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

impl ClientMap {
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap::default()
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, id: &str, name: &str, user_id: UserId, client: Client) {
        let id = id.to_owned();
        let password_policy = Self::current_policy(&self.password_policy);
        let record = ClientRecord {
            id: id.clone(),
            user_id,
            name: name.to_owned(),
            encoded_client: client.encode(password_policy),
            scopes: Vec::<crate::oauth::rhodos_scopes::Scopes>::new(),
        };
        self.clients
            .insert(id, record);
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

impl Registrar for ClientMap {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.clients.get(bound.client_id.as_ref()) {
            None => return Err(RegistrarError::Unspecified),
            Some(stored) => stored,
        };

        // Perform exact matching as motivated in the rfc
        let registered_url = match bound.redirect_uri {
            None => client.encoded_client.redirect_uri.clone(),
            Some(ref url) => {
                let original = std::iter::once(&client.encoded_client.redirect_uri);
                let alternatives = client.encoded_client.additional_redirect_uris.iter();
                if let Some(registered) = original
                    .chain(alternatives)
                    .find(|&registered| *registered == *url.as_ref())
                {
                    registered.clone()
                } else {
                    return Err(RegistrarError::Unspecified);
                }
            }
        };

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_url),
        })
    }

    /// Always overrides the scope with a default scope.
    fn negotiate(&self, bound: BoundClient, _scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        let client = self
            .clients
            .get(bound.client_id.as_ref())
            .expect("Bound client appears to not have been constructed with this registrar");
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.encoded_client.default_scope.clone(),
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        self.clients
            .get(client_id)
            .ok_or(RegistrarError::Unspecified)
            .and_then(|client| {
                RegisteredClient::new(&client.encoded_client, password_policy).check_authentication(passphrase)
            })?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub user_id: UserId,
    pub (crate) encoded_client: EncodedClient,
    pub scopes: Vec<crate::oauth::rhodos_scopes::Scopes>
}

impl ClientRecord {
    fn encoded_client(&self) -> EncodedClient {
        self.encoded_client.clone()
    }
}
