pub mod auth;
pub mod index;
pub mod user;

pub mod request_io;

use actix_web::dev::HttpResponseBuilder;
use actix_web::http::{header, StatusCode};
use actix_web::HttpResponse;
use std::fmt;

// TODO: Move all expensive operations inside actix_web::web::block closures

pub trait HandlerError {}

#[derive(Debug)]
pub enum RequestError {
    InvalidFormat(Option<String>),
    UserUnauthorized(Option<String>),
    AccessForbidden(Option<String>),
}

#[derive(Debug)]
pub enum ServerError {
    InternalServerError(Option<String>),
    DatabaseTransactionError(Option<String>),
}

impl HandlerError for RequestError {}
impl HandlerError for ServerError {}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::InvalidFormat(msg) => format_err(f, "Invalid request format", &msg),
            RequestError::UserUnauthorized(msg) => format_err(f, "User unauthorized", &msg),
            RequestError::AccessForbidden(msg) => format_err(f, "Access forbidden", &msg),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::InternalServerError(msg) => format_err(f, "Internal server error", &msg),
            ServerError::DatabaseTransactionError(msg) => {
                format_err(f, "Database transaction failed", &msg)
            }
        }
    }
}

impl actix_web::error::ResponseError for RequestError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            RequestError::InvalidFormat(_) => StatusCode::BAD_REQUEST,
            RequestError::UserUnauthorized(_) => StatusCode::UNAUTHORIZED,
            RequestError::AccessForbidden(_) => StatusCode::FORBIDDEN,
        }
    }
}

impl actix_web::error::ResponseError for ServerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn format_err(f: &mut fmt::Formatter<'_>, error_txt: &str, msg: &Option<String>) -> fmt::Result {
    write!(
        f,
        "{}{}",
        error_txt,
        if msg.is_some() {
            format!(": {}", msg.as_ref().unwrap())
        } else {
            String::new()
        }
    )
}
