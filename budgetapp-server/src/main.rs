#[macro_use]
extern crate diesel;
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut port = 9000u16;
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

    let cpu_count = num_cpus::get().try_into().expect("Failed to represent CPU count");

    let actix_workers = if let Some(count) = env::CONF.workers.actix_workers {
        count
    } else {
        cpu_count
    };

    let db_workers = if let Some(count) = env::CONF.connections.max_db_connections {
        count
    } else {
        cpu_count as u32 * 2
    };

    log::info!("Connecting to database...");

    // To prevent resource starvation, max connections must be at least as large as the number of
    // actix workers,
    let db_max_connections = if actix_workers > db_workers as usize {
        actix_workers as u32
    } else {
        db_workers
    };

    let db_connection_manager =
        ConnectionManager::<PgConnection>::new(env::CONF.connections.database_uri.as_str());
    let db_thread_pool = match r2d2::Pool::builder()
        .max_size(db_max_connections)
        .build(db_connection_manager)
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Failed to connect to database");
            std::process::exit(1);
        }
    };

    log::info!("Successfully connected to database");

    // Declaring a vec of job runners here to give it the same lifetime as the HTTP server
    let mut runners = Vec::new();

    if schedule_cron_jobs {
        let db_thread_pool_ref = db_thread_pool.clone();

        let clear_otp_verification_count_job = move || {
            let mut db_connection = db_thread_pool_ref
                .get()
                .expect("Failed to get thread for connecting to db");

            if utils::db::auth::clear_otp_verification_count(&mut db_connection).is_err() {
                return Err(cron::CronJobError::JobFailure(Some(
                    "Failed to clear recent OTP verfications",
                )));
            }

            Ok(())
        };

        let db_thread_pool_ref = db_thread_pool.clone();

        let clear_password_attempt_count_job = move || {
            let mut db_connection = db_thread_pool_ref
                .get()
                .expect("Failed to get thread for connecting to db");

            if utils::db::auth::clear_password_attempt_count(&mut db_connection).is_err() {
                return Err(cron::CronJobError::JobFailure(Some(
                    "Failed to clear recent password attempts",
                )));
            }

            Ok(())
        };

        let db_thread_pool_ref = db_thread_pool.clone();

        let clear_expired_blacklisted_tokens_job = move || {
            let mut db_connection = db_thread_pool_ref
                .get()
                .expect("Failed to get thread for connecting to db");

            if utils::db::auth::clear_all_expired_refresh_tokens(&mut db_connection).is_err() {
                return Err(cron::CronJobError::JobFailure(Some(
                    "Failed to clear expired refresh tokens",
                )));
            }

            Ok(())
        };

        const SECONDS_IN_DAY: u64 = 86_400;
        let long_lifetime_runner =
            cron::Runner::with_granularity(Duration::from_secs(SECONDS_IN_DAY));

        let otp_attempts_reset_runner = cron::Runner::with_granularity(Duration::from_secs(
            TryInto::<u64>::try_into(env::CONF.security.otp_attempts_reset_mins)
                .expect("Invalid otp_attempts_reset_mins config")
                * 60,
        ));

        let password_attempts_reset_runner = cron::Runner::with_granularity(Duration::from_secs(
            TryInto::<u64>::try_into(env::CONF.security.password_attempts_reset_mins)
                .expect("Invalid password_attempts_reset_mins config")
                * 60,
        ));

        long_lifetime_runner.add_job(
            clear_expired_blacklisted_tokens_job,
            String::from("Clear expired blacklisted refresh tokens"),
        );

        otp_attempts_reset_runner.add_job(
            clear_otp_verification_count_job,
            String::from("Clear OTP Verificaiton"),
        );

        password_attempts_reset_runner.add_job(
            clear_password_attempt_count_job,
            String::from("Clear Password Attemps"),
        );

        runners.push(long_lifetime_runner);
        runners.push(otp_attempts_reset_runner);
        runners.push(password_attempts_reset_runner);
    }

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db_thread_pool.clone()))
            .configure(services::api::configure)
            .configure(services::web::configure)
            .wrap(Logger::default())
    })
    .workers(actix_workers)
    .bind(base_addr)?
    .run()
    .await?;

    // Log something so the runners vec doesn't get optimized away. This won't actually be
    // reached.
    for _ in runners {
        log::info!("Shutting down cron job runner...");
    }

    Ok(())
}
