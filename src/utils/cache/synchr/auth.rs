// use std::net::IpAddr;
use log::error;

use crate::definitions::*;
use crate::utils::cache::RedisError;

pub fn clear_recent_otp_verifications(
    redis_connection: &mut RedisSyncConnection,
) -> Result<(), RedisError> {
    match redis::cmd("DEL")
        .arg("budgetapp:otp:user_recent_verification_counts")
        .query::<u64>(redis_connection)
    {
        Ok(_) => Ok(()),
        Err(_) => {
            error!("Clearing OTP verification cache failed");
            Err(RedisError::CommandFailed(Some(
                "Clearing OTP verification cache failed",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::Uuid;

    use crate::env;
    use crate::utils::cache::asynchr::auth::get_and_incr_recent_otp_verifications;

    // Ignore test because it will interfere with other tests if they are run with more than one thread
    // To run all tests, run `cargo test -- --include-ignored --test-threads=1`
    #[actix_rt::test]
    #[ignore]
    async fn test_clear_recent_otp_verifications() {
        let user_id = Uuid::new_v4();

        let redis_client = redis::Client::open(env::CONF.connections.redis_uri.clone())
            .expect("Connection to Redis failed");
        let mut redis_async_connection = redis_client.get_async_connection().await.unwrap();

        for i in 1..=5 {
            let res = get_and_incr_recent_otp_verifications(&mut redis_async_connection, &user_id)
                .await
                .unwrap();
            assert_eq!(res, i);
        }

        let mut redis_sync_connection = redis_client.get_connection().unwrap();
        clear_recent_otp_verifications(&mut redis_sync_connection).unwrap();

        // Make sure table was cleared
        let res = get_and_incr_recent_otp_verifications(&mut redis_async_connection, &user_id)
            .await
            .unwrap();
        assert_eq!(res, 1);
    }
}
