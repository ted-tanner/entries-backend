use budgetapp_utils::budget_token::BudgetToken;

use actix_web::dev::Payload;
use actix_web::{error, FromRequest, HttpRequest};
use futures::future;

impl FromRequest for BudgetToken {
    type Error = error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const NO_BUDGET_TOKEN_HEADER_MESSAGE: &str = "BudgetToken header is missing or invalid";

        let budget_token_header = match req.headers().get("BudgetToken") {
            Some(header) => header,
            None => return future::err(error::ErrorBadRequest(NO_BUDGET_TOKEN_HEADER_MESSAGE)),
        };

        let token = match budget_token_header.to_str() {
            Ok(t) => t,
            Err(_) => return future::err(error::ErrorBadRequest(NO_BUDGET_TOKEN_HEADER_MESSAGE)),
        };

        let token = match BudgetToken.from_str(token) {
            Ok(t) => t,
            Err(_) => return future::err(error::ErrorBadRequest(NO_BUDGET_TOKEN_HEADER_MESSAGE)),
        };

        future::ok(token)
    }
}
