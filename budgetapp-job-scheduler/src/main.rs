#[macro_use]
extern crate lazy_static;

use std::time::Duration;

mod env;
mod jobs;
mod runner;

fn main() {
    println!("{:#?}", *env::CONF);

    let job = jobs::Job::new(Duration::from_secs(env::CONF.clear_otp_attempts_job.job_frequency_secs), || {
        println!("I am inside the job executor!");

        Ok(())
    });

    // let mut runners = Vec::new();

    // if schedule_cron_jobs {
    //     let db_thread_pool_ref = db_thread_pool.clone();

    //     let clear_otp_verification_count_job = move || {
    //         let mut db_connection = db_thread_pool_ref
    //             .get()
    //             .expect("Failed to get thread for connecting to db");

    //         if utils::db::auth::clear_otp_verification_count(&mut db_connection).is_err() {
    //             return Err(cron::CronJobError::JobFailure(Some(
    //                 "Failed to clear recent OTP verfications",
    //             )));
    //         }

    //         Ok(())
    //     };

    //     let db_thread_pool_ref = db_thread_pool.clone();

    //     let clear_password_attempt_count_job = move || {
    //         let mut db_connection = db_thread_pool_ref
    //             .get()
    //             .expect("Failed to get thread for connecting to db");

    //         if utils::db::auth::clear_password_attempt_count(&mut db_connection).is_err() {
    //             return Err(cron::CronJobError::JobFailure(Some(
    //                 "Failed to clear recent password attempts",
    //             )));
    //         }

    //         Ok(())
    //     };

    //     let db_thread_pool_ref = db_thread_pool.clone();

    //     let clear_expired_blacklisted_tokens_job = move || {
    //         let mut db_connection = db_thread_pool_ref
    //             .get()
    //             .expect("Failed to get thread for connecting to db");

    //         if utils::db::auth::clear_all_expired_refresh_tokens(&mut db_connection).is_err() {
    //             return Err(cron::CronJobError::JobFailure(Some(
    //                 "Failed to clear expired refresh tokens",
    //             )));
    //         }

    //         Ok(())
    //     };

    //     const SECONDS_IN_DAY: u64 = 86_400;
    //     let long_lifetime_runner =
    //         cron::Runner::with_granularity(Duration::from_secs(SECONDS_IN_DAY));

    //     let otp_attempts_reset_runner = cron::Runner::with_granularity(Duration::from_secs(
    //         TryInto::<u64>::try_into(env::CONF.security.otp_attempts_reset_mins)
    //             .expect("Invalid otp_attempts_reset_mins config")
    //             * 60,
    //     ));

    //     let password_attempts_reset_runner = cron::Runner::with_granularity(Duration::from_secs(
    //         TryInto::<u64>::try_into(env::CONF.security.password_attempts_reset_mins)
    //             .expect("Invalid password_attempts_reset_mins config")
    //             * 60,
    //     ));

    //     long_lifetime_runner.add_job(
    //         clear_expired_blacklisted_tokens_job,
    //         String::from("Clear expired blacklisted refresh tokens"),
    //     );

    //     otp_attempts_reset_runner.add_job(
    //         clear_otp_verification_count_job,
    //         String::from("Clear OTP Verificaiton"),
    //     );

    //     password_attempts_reset_runner.add_job(
    //         clear_password_attempt_count_job,
    //         String::from("Clear Password Attemps"),
    //     );

    //     runners.push(long_lifetime_runner);
    //     runners.push(otp_attempts_reset_runner);
    //     runners.push(password_attempts_reset_runner);
    // }
}
