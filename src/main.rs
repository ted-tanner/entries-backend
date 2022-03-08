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
use std::time::Duration;

mod cron;
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
    let mut schedule_cron_jobs = false;

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
            "--schedule-cron-jobs" => {
                schedule_cron_jobs = true;

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
        ConnectionManager::<PgConnection>::new(env::CONF.connections.database_uri.as_str());
    let db_thread_pool = match r2d2::Pool::builder().build(db_connection_manager) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Failed to connect to database");
            std::process::exit(1);
        }
    };

    log::info!("Successfully connected to database");

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

    log::info!("Connecting to Redis...");

    let redis_client = match redis::Client::open(&*env::CONF.connections.redis_uri) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Failed to connect to Redis");
            std::process::exit(1);
        }
    };
    
    {
        // Test connection to Redis (then drop the test connection)
        match redis_client.get_connection() {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Failed to connect to Redis");
                std::process::exit(1);
            }
        };

        log::info!("Successfully connected to Redis");
    }

    // Declaring a vec of job runners here to give it the same lifetime as the HTTP server
    let mut runners = Vec::new();

    if schedule_cron_jobs {
        let clear_otp_verification_count_job = move || {
            let redis_client = match redis::Client::open(&*env::CONF.connections.redis_uri) {
                Ok(c) => c,
                Err(_) => {
                    return Err(cron::CronJobError::JobFailure(Some(
                        "Failed to connect to Redis",
                    )));
                }
            };

            let mut redis_connection = match redis_client.get_connection() {
                Ok(c) => c,
                Err(_) => {
                    return Err(cron::CronJobError::JobFailure(Some(
                        "Failed to connect to Redis",
                    )));
                }
            };

            if utils::cache::synchr::auth::clear_recent_otp_verifications(&mut redis_connection)
                .is_err()
            {
                return Err(cron::CronJobError::JobFailure(Some(
                    "Failed to clear recent OTP verfications",
                )));
            }

            Ok(())
        };

        let cron_job_db_connection = db_thread_pool
            .get()
            .expect("Failed to access database thread pool");

        let clear_expired_blacklisted_tokens_job = move || {
            if utils::db::auth::clear_all_expired_refresh_tokens(&cron_job_db_connection).is_err() {
                return Err(cron::CronJobError::JobFailure(Some(
                    "Failed to clear expired refresh tokens",
                )));
            }

            Ok(())
        };

        const SECONDS_IN_DAY: u64 = 86_400;
        let long_lifetime_runner =
            cron::Runner::with_granularity(Duration::from_secs(SECONDS_IN_DAY));

        let short_lifetime_runner = cron::Runner::with_granularity(Duration::from_secs(
            env::CONF.lifetimes.otp_lifetime_mins * 2 * 60 + 1,
        ));

        long_lifetime_runner.add_job(
            clear_expired_blacklisted_tokens_job,
            String::from("Clear expired blacklisted refresh tokens"),
        );

        short_lifetime_runner.add_job(
            clear_otp_verification_count_job,
            String::from("Clear OTP Verificaiton"),
        );

        runners.push(short_lifetime_runner);
    }

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db_thread_pool.clone()))
	    .app_data(Data::new(redis_client.clone()))
            .configure(services::api::configure)
            .configure(services::index::configure)
            .wrap(Logger::default())
    })
    .workers(env::CONF.workers.actix_workers)
    .bind(base_addr)?
    .run()
    .await
}
