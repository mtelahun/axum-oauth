use std::{borrow::Cow, collections::HashMap};

use once_cell::sync::Lazy;
use oxide_auth::{
    endpoint::{PreGrant, Registrar},
    primitives::{
        registrar::{
            Argon2, BoundClient, Client, ClientUrl, EncodedClient, PasswordPolicy,
            RegisteredClient, RegistrarError,
        },
        scope::Scope,
    },
};

use crate::oauth::scopes;

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(Argon2::default);

#[derive(Default)]
pub struct ClientMap {
    pub(crate) clients: HashMap<String, ClientRecord>,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

impl ClientMap {
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap::default()
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, id: &str, name: &str, client: Client) {
        let id = id.to_owned();
        let password_policy = Self::current_policy(&self.password_policy);
        let record = ClientRecord {
            id: id.clone(),
            name: name.to_owned(),
            encoded_client: client.encode(password_policy),
        };
        self.clients.insert(id, record);
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy(policy: &Option<Box<dyn PasswordPolicy>>) -> &dyn PasswordPolicy {
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

                original
                    .chain(alternatives)
                    .find(|&registered| *registered == *url.as_ref())
                    .cloned()
                    .ok_or(RegistrarError::Unspecified)?
            }
        };

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_url),
        })
    }

    /// Always overrides the scope with a default scope.
    fn negotiate(
        &self,
        bound: BoundClient,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client = self
            .clients
            .get(bound.client_id.as_ref())
            .expect("Bound client appears to not have been constructed with this registrar");

        let scope = scope
            .and_then(|scope| {
                scope
                    .iter()
                    .filter(|scope| scopes::SCOPES.contains(scope))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .parse()
                    .ok()
            })
            .unwrap_or(client.encoded_client.default_scope.clone());

        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope,
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        tracing::debug!("Registrar: check()");
        let password_policy = Self::current_policy(&self.password_policy);

        self.clients
            .get(client_id)
            .ok_or(RegistrarError::Unspecified)
            .and_then(|client| {
                RegisteredClient::new(&client.encoded_client, password_policy)
                    .check_authentication(passphrase)
            })?;

        tracing::debug!("Registrar: client check successfull");
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub(crate) encoded_client: EncodedClient,
}

impl ClientRecord {
    #[allow(dead_code)]
    fn encoded_client(&self) -> EncodedClient {
        self.encoded_client.clone()
    }
}
