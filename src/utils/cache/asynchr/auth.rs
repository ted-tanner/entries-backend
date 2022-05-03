// use std::net::IpAddr;
use log::error;
use uuid::Uuid;

use crate::definitions::*;
use crate::utils::cache::RedisError;

// pub fn get_and_incr_recent_user_creations(
//     redis_connection: &RedisAsyncConnection,
//     ip_addr: &IpAddr,
// ) -> Result<u64, RedisError> {
// }

// pub fn get_and_incr_recent_signins(
//     redis_connection: &RedisAsyncConnection,
//     ip_addr: &IpAddr,
// ) -> Result<u64, RedisError> {
// }

pub async fn get_and_incr_recent_otp_verifications(
    redis_connection: &mut RedisAsyncConnection,
    user_id: Uuid,
) -> Result<u64, RedisError> {
    match redis::cmd("HINCRBY")
        .arg("budgetapp:otp:user_recent_verification_counts")
        .arg(user_id.as_u128().to_string())
        .arg(1u8)
        .query_async::<_, u64>(redis_connection)
        .await
    {
        Ok(a) => Ok(a),
        Err(_) => {
            error!("Incrementing recent OTP verification failed for user with ID {user_id}");
            Err(RedisError::CommandFailed(Some(
                "Incrementing recent OTP verification failed",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use uuid::Uuid;

    use crate::env;

    #[actix_rt::test]
    async fn test_get_and_incr_recent_otp_verifications() {
        let user_id = Uuid::new_v4();
        let redis_client = redis::Client::open(env::CONF.connections.redis_uri.clone())
            .expect("Connection to Redis failed");
        let mut redis_connection = redis_client.get_async_connection().await.unwrap();

        for i in 1..=10 {
            let res = get_and_incr_recent_otp_verifications(&mut redis_connection, user_id)
                .await
                .unwrap();
            assert_eq!(res, i);
        }
    }
}
