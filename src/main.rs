#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate lazy_static;

use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use env_logger::Env;
use std::net::{IpAddr, Ipv4Addr};

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
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut port = 9000u16;
    let mut run_migrations = false;

    let mut args = std::env::args();

    // Eat the first argument, which is the relative path to the executable
    args.next();

    while let Some(arg) = args.next() {
        match arg.to_lowercase().as_str() {
            "--port" => {
                let port_str = {
                    let next_arg = args.next();

                    match next_arg {
                        Some(s) => s,
                        None => {
                            eprintln!("--port option specified but no port was given");
                            std::process::exit(1);
                        }
                    }
                };

                port = {
                    let port_result = port_str.parse::<u16>();

                    match port_result {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("Incorrect format for port. Integer expected");
                            std::process::exit(1);
                        }
                    }
                };

                continue;
            }
            "--ip" => {
                ip = {
                    let next_arg = args.next();

                    match next_arg {
                        Some(s) => match s.parse::<IpAddr>() {
                            Ok(i) => i,
                            Err(_) => {
                                eprintln!("Invalid IP address");
                                std::process::exit(1);
                            }
                        },
                        None => {
                            eprintln!("--ip option specified but no IP was given");
                            std::process::exit(1);
                        }
                    }
                };

                continue;
            }
            "--run-migrations" => {
                run_migrations = true;

                continue;
            }
            a => {
                eprintln!("Invalid argument: {}", &a);
                std::process::exit(1);
            }
        }
    }

    let base_addr = format!("{}:{}", &ip, &port);

    env::initialize();

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("Connecting to database...");

    let db_connection_manager =
        ConnectionManager::<PgConnection>::new(env::CONF.connections.database_url.as_str());
    let db_thread_pool = r2d2::Pool::builder()
        .build(db_connection_manager)
        .expect("Failed to create database thread pool");

    log::info!("Successfully connected to database");

    let redis_conf = deadpool_redis::Config::from_url(&env::CONF.connections.redis_url);
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
            .app_data(Data::new(db_thread_pool.clone()))
            .app_data(Data::new(redis_thread_pool.clone()))
            .configure(services::api::configure)
            .configure(services::index::configure)
            .wrap(Logger::default())
    })
    .workers(env::CONF.workers.actix_workers)
    .bind(base_addr)?
    .run()
    .await
}
