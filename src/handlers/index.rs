pub mod get {
    use actix_web::{HttpResponse, Responder};

    pub async fn index() -> impl Responder {
        HttpResponse::Ok()
    }

    pub async fn heartbeat() -> impl Responder {
        HttpResponse::Ok()
    }
}
