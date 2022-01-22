use deadpool_redis::redis;
// use std::net::IpAddr;
use uuid::Uuid;

use crate::definitions::*;
use crate::utils::redis::RedisError;

// pub fn get_and_incr_recent_user_creations(
//     redis_connection: &RedisConnection,
//     ip_addr: &IpAddr,
// ) -> Result<u64, RedisError> {
// }

// pub fn get_and_incr_recent_signins(
//     redis_connection: &RedisConnection,
//     ip_addr: &IpAddr,
// ) -> Result<u64, RedisError> {
// }

pub async fn get_and_incr_recent_otp_verifications(
    redis_connection: &mut RedisConnection,
    user_id: &Uuid,
) -> Result<u64, RedisError> {
    match redis::cmd("INCR")
        .arg(format!("budgetapp:otp:users:{}", user_id.as_u128()))
        .query_async::<_, u64>(redis_connection)
        .await
    {
        Ok(a) => Ok(a),
        Err(_) => Err(RedisError::QueryFailed(None)),
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
        let mut redis_connection = (*env::testing::REDIS_THREAD_POOL).get().await.unwrap();

        for i in 1..=15 {
            let res = get_and_incr_recent_otp_verifications(&mut redis_connection, &user_id)
                .await
                .unwrap();
            assert_eq!(res, i);
        }
    }
}
