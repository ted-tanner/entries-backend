use entries_common::db::create_db_thread_pool;
use entries_common::email::senders::{AmazonSes, MockSender};
use entries_common::email::SendEmail;

use actix_protobuf::ProtoBufConfig;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming, WriteMode};
use std::sync::Arc;
use zeroize::Zeroizing;

mod env;
mod handlers;
mod middleware;
mod services;

use services::api::RouteLimiters;

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

    let db_thread_pool = create_db_thread_pool(
        &db_uri,
        env::CONF.db_max_connections,
        env::CONF.db_idle_timeout,
    );

    log::info!("Successfully connected to database");

    let smtp_thread_pool: Arc<Box<dyn SendEmail>> = if env::CONF.email_enabled {
        log::info!("Connecting to SMTP relay...");

        let smtp_thread_pool = AmazonSes::with_credentials(
            &env::CONF.amazon_ses_username,
            &env::CONF.amazon_ses_key,
            &env::CONF.smtp_address,
            env::CONF.max_smtp_connections,
            env::CONF.smtp_idle_timeout,
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

    let db_thread_pool = Data::new(db_thread_pool);
    let smtp_thread_pool = Data::new(smtp_thread_pool);

    let limiters = RouteLimiters::default();

    HttpServer::new(move || {
        let mut protobuf_config = ProtoBufConfig::default();
        protobuf_config.limit(env::CONF.protobuf_max_size);

        App::new()
            .app_data(protobuf_config)
            .app_data(db_thread_pool.clone())
            .app_data(smtp_thread_pool.clone())
            .configure(|cfg| services::api::configure(cfg, limiters.clone()))
            .wrap(actix_web::middleware::Compress::default())
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
