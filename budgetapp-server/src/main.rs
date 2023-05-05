#[macro_use]
extern crate lazy_static;

use actix_http::header::http_percent_encode;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use flexi_logger::{
    Age, Cleanup, Criterion, Duplicate, FileSpec, LogSpecification, Logger, Naming, WriteMode,
};
use std::net::{IpAddr, Ipv4Addr};

mod env;
mod handlers;
mod middleware;
mod services;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut port = 9000u16;

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
                            eprintln!("ERROR: --port option specified but no port was given");
                            std::process::exit(1);
                        }
                    }
                };

                port = {
                    let port_result = port_str.parse::<u16>();

                    match port_result {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("ERROR: Incorrect format for port. Integer expected");
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
                                eprintln!("ERROR: Invalid IP address");
                                std::process::exit(1);
                            }
                        },
                        None => {
                            eprintln!("ERROR: --ip option specified but no IP was given");
                            std::process::exit(1);
                        }
                    }
                };

                continue;
            }
            a => {
                eprintln!("ERROR: Invalid argument: {}", &a);
                std::process::exit(1);
            }
        }
    }

    let base_addr = format!("{}:{}", &ip, &port);

    let _logger = Logger::with(LogSpecification::info())
        .log_to_file(FileSpec::default().directory("./logs"))
        .rotate(
            Criterion::Age(Age::Day),
            Naming::Timestamps,
            Cleanup::KeepLogAndCompressedFiles(60, 365),
        )
        .cleanup_in_background_thread(true)
        .duplicate_to_stdout(Duplicate::All)
        .write_mode(WriteMode::Async)
        .format(|writer, now, record| {
            write!(
                writer,
                "{:5} | {} | {}:{} | {}",
                record.level(),
                now.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
                record.module_path().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .use_utc()
        .start()
        .expect("Failed to start logger");

    env::initialize();

    let cpu_count = num_cpus::get();

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
            eprintln!("ERROR: Failed to connect to database");
            std::process::exit(1);
        }
    };

    log::info!("Successfully connected to database");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db_thread_pool.clone()))
            .configure(services::api::configure)
            .configure(services::web::configure)
            .wrap(actix_web::middleware::Logger::default())
    })
    .workers(actix_workers)
    .bind(base_addr)?
    .run()
    .await?;

    Ok(())
}
