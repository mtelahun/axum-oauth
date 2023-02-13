pub const SCOPES: &[&str] = &[
    Account::READ,
    Account::WRITE,
    Account::FOLLOW,
];

pub trait Resource {
    const READ: &'static str;
    const WRITE: &'static str;
    const FOLLOW: &'static str;
}

pub struct Account;

impl Resource for Account {
    const READ: &'static str = "account:read";
    const WRITE: &'static str = "account:write";
    const FOLLOW: &'static str = "account:follow";
}

#[derive(Debug)]
pub enum Scopes {
    AccountRead,
    AccountWrite,
    AccountFollow,
}

impl std::str::FromStr for Scopes {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            Account::READ => Self::AccountRead,
            Account::WRITE => Self::AccountWrite,
            Account::FOLLOW => Self::AccountFollow,
            _ => return Err(()),
        })
    }
}

pub struct Read<S>(pub S);
pub struct Write<S>(pub S);
pub struct Follow<S>(pub S);

pub trait Scope {
    const SCOPE: &'static str;
}

impl Scope for () {
    const SCOPE: &'static str = "";
}

impl<S: Resource> Scope for Read<S> {
    const SCOPE: &'static str = S::READ;
}

impl<S: Resource> Scope for Write<S> {
    const SCOPE: &'static str = S::WRITE;
}

impl<S: Resource> Scope for Follow<S> {
    const SCOPE: &'static str = S::FOLLOW;
}
