#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate lazy_static;

use actix_web::{middleware::Logger, App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use env_logger::Env;

mod db_utils;
mod definitions;
mod env;
mod handlers;
mod middleware;
mod models;
mod schema;
mod services;
mod utils;

diesel_migrations::embed_migrations!();

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut ip = String::from("127.0.0.1");
    let mut port = 9000u16;
    let mut run_migrations = false;

    let mut args = std::env::args();

    // Eat the first argument, which is the relative path to the executable
    args.next();

    while let Some(arg) = args.next() {
        match arg.to_lowercase().as_str() {
            "--port" => {
                let port_str = args
                    .next()
                    .expect("--port option specified but no port was given");

                port = port_str
                    .parse()
                    .expect("Wrong format for port. Integer expected");

                continue;
            }
            "--ip" => {
                ip = args
                    .next()
                    .expect("--ip option specified but no IP was given")
                    .to_string();

                continue;
            }
            "--run-migrations" => {
                run_migrations = true;

                continue;
            }
            a => panic!("Invalid argument: {}", &a),
        }
    }

    let base_addr = format!("{}:{}", &ip, &port);

    env::initialize();

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("Connecting to database...");

    let db_connection_manager =
        ConnectionManager::<PgConnection>::new(env::db::DATABASE_URL.as_str());
    let db_thread_pool = r2d2::Pool::builder()
        .build(db_connection_manager)
        .expect("Failed to create database thread pool");

    log::info!("Successfully connected to database");

    let redis_conf = deadpool_redis::Config::from_url(&*env::cache::REDIS_URL);
    let redis_thread_pool = redis_conf
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("Failed to create Redis cache thread pool");

    if run_migrations {
        log::info!("Running migrations...");

        let db_connection = &db_thread_pool
            .get()
            .expect("Failed to get thread for connecting to db");
        match embedded_migrations::run_with_output(db_connection, &mut std::io::stdout()) {
            Ok(_) => log::info!("Migrations run successfully"),
            Err(e) => log::error!("Error running migrations: {}", e.to_string()),
        }
    }

    HttpServer::new(move || {
        App::new()
            .data(db_thread_pool.clone())
            .data(redis_thread_pool.clone())
            .configure(services::api::configure)
            .configure(services::index::configure)
            .wrap(Logger::default())
    })
    .bind(base_addr)?
    .run()
    .await
}
