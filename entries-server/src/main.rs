use entries_utils::email::senders::{AmazonSes, MockSender};
use entries_utils::email::SendEmail;

use actix_protobuf::ProtoBufConfig;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming, WriteMode};
use std::sync::Arc;
use zeroize::Zeroizing;

mod env;
mod handlers;
mod middleware;
mod services;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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
            a => {
                eprintln!("ERROR: Invalid argument: {}", &a);
                std::process::exit(1);
            }
        }
    }

    let base_addr = format!("127.0.0.1:{}", &port);

    let _logger = Logger::try_with_str(&env::CONF.log_level)
        .expect(
            "Invalid log level. Options: ERROR, WARN, INFO, DEBUG, TRACE. \
             Example: `info, my::critical::module=trace`",
        )
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

    log::info!("Connecting to database...");

    let db_uri = Zeroizing::new(format!(
        "postgres://{}:{}@{}:{}/{}",
        env::CONF.db_username,
        env::CONF.db_password,
        env::CONF.db_hostname,
        env::CONF.db_port,
        env::CONF.db_name,
    ));

    let db_connection_manager = ConnectionManager::<PgConnection>::new(db_uri.as_str());
    let db_thread_pool = match r2d2::Pool::builder()
        .max_size(env::CONF.db_max_connections)
        .idle_timeout(Some(env::CONF.db_idle_timeout_secs))
        .build(db_connection_manager)
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("ERROR: Failed to connect to database");
            std::process::exit(1);
        }
    };

    log::info!("Successfully connected to database");

    let smtp_thread_pool: Arc<Box<dyn SendEmail>> = if env::CONF.email_enabled {
        log::info!("Connecting to SMTP relay...");

        let smtp_thread_pool = AmazonSes::with_credentials(
            &env::CONF.amazon_ses_username,
            &env::CONF.amazon_ses_key,
            &env::CONF.smtp_address,
            env::CONF.max_smtp_connections,
            env::CONF.smtp_idle_timeout_secs,
        )
        .expect("Failed to connect to SMTP relay");

        match smtp_thread_pool.test_connection().await {
            Ok(true) => (),
            Ok(false) => panic!("Failed to connect to SMTP relay"),
            Err(e) => panic!("Failed to connect to SMTP relay: {e}"),
        }

        log::info!("Successfully connected to SMTP relay");

        Arc::new(Box::new(smtp_thread_pool))
    } else {
        log::info!("Emails are disabled. Using mock SMTP thread pool.");
        Arc::new(Box::new(MockSender::new()))
    };

    let mut protobuf_config = ProtoBufConfig::default();
    protobuf_config.limit(1024 * 1024 * 250); // 250 MB

    let protobuf_config = Data::new(protobuf_config);
    let db_thread_pool = Data::new(db_thread_pool);
    let smtp_thread_pool = Data::from(smtp_thread_pool);

    HttpServer::new(move || {
        App::new()
            .app_data(protobuf_config.clone())
            .app_data(db_thread_pool.clone())
            .app_data(smtp_thread_pool.clone())
            .configure(services::api::configure)
            .configure(services::web::configure)
            .wrap(actix_web::middleware::Logger::default())
    })
    .workers(env::CONF.actix_worker_count)
    .bind(base_addr)?
    .run()
    .await?;

    unsafe {
        env::CONF.zeroize();
    }

    Ok(())
}
