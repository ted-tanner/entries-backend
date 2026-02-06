use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future::{ready, Ready};

use crate::handlers::BROWSER_CLIENT_HEADER;

#[derive(Copy, Clone, Debug)]
pub struct ClientType(bool);

impl ClientType {
    pub fn is_browser(&self) -> bool {
        self.0
    }
}

impl FromRequest for ClientType {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let is_browser = req.headers().contains_key(BROWSER_CLIENT_HEADER);
        ready(Ok(ClientType(is_browser)))
    }
}
