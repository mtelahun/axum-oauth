use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Database {
        source: crate::oauth::database::StoreError,
    },
    NotFound,
    InvalidKey {
        source: crate::oauth::models::InvalidLengthError,
    },
    Hash {
        source: argon2::password_hash::Error,
    },
    OAuth {
        source: oxide_auth_axum::WebError,
    },
    ResourceConflict,
    InternalError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[allow(unused_variables)]
            Error::Database { source } => write!(f, "Database error"),
            Error::NotFound => write!(f, "Not found"),
            #[allow(unused_variables)]
            Error::InvalidKey { source } => write!(f, "Invalid key"),
            #[allow(unused_variables)]
            Error::Hash { source } => write!(f, "Invalid hash in database"),
            Error::OAuth { source } => write!(f, "{source}"),
            Error::InternalError => write!(f, "Unexpected internal error"),
            Error::ResourceConflict => write!(f, "User already exists"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Database { source } => Some(source),
            Error::NotFound => None,
            Error::InvalidKey { source } => Some(source),
            Error::Hash { source } => Some(source),
            Error::OAuth { source } => Some(source),
            Error::InternalError => None,
            Error::ResourceConflict => None,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if let Self::OAuth { source } = self {
            source.into_response()
        } else if let Self::ResourceConflict = self {
            (StatusCode::CONFLICT, "User already exists").into_response()
        } else {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
