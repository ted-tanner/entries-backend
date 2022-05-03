use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::definitions::*;
use crate::schema::blacklisted_tokens as token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

pub fn clear_all_expired_refresh_tokens(
    db_connection: &DbConnection,
) -> Result<usize, diesel::result::Error> {
    // Add two minutes to current time to prevent slight clock differences/inaccuracies from
    // opening a window for an attacker to use an expired refresh token
    let current_unix_epoch: i64 = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to fetch system time")
        .as_secs()
        + 120)
        .try_into()
        .expect("Seconds since Unix Epoch is too big to be stored in a signed 64-bit integer");

    diesel::delete(
        blacklisted_tokens.filter(token_fields::token_expiration_time.lt(current_unix_epoch)),
    )
    .execute(db_connection)
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::web::Json;
    use chrono::NaiveDate;
    use diesel::{dsl, RunQueryDsl};
    use rand::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::env;
    use crate::handlers::request_io::InputUser;
    use crate::models::blacklisted_token::NewBlacklistedToken;
    use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use crate::utils::db::user;
    use crate::utils::jwt;

    #[actix_rt::test]
    async fn test_clear_all_expired_refresh_tokens() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_number: u32 = rand::thread_rng().gen_range::<u32, _>(10_000_000..100_000_000);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        user::create_user(&db_connection, &Json(new_user.clone())).unwrap();
        let user_id = user::get_user_by_email(&db_connection, &new_user.email)
            .unwrap()
            .id;

        let jwt_params = jwt::JwtParams {
            user_id: &user_id,
            user_email: &new_user.email,
            user_currency: &new_user.currency,
        };

        let pretend_expired_token = jwt::generate_refresh_token(jwt_params.clone()).unwrap();
        let unexpired_token = jwt::generate_refresh_token(jwt_params).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_blacklisted = NewBlacklistedToken {
            token: &pretend_expired_token.to_string(),
            user_id,
            token_expiration_time: (current_time - 3600).try_into().unwrap(),
        };

        let unexpired_blacklisted = NewBlacklistedToken {
            token: &unexpired_token.to_string(),
            user_id,
            token_expiration_time: (current_time + 3600).try_into().unwrap(),
        };

        dsl::insert_into(blacklisted_tokens)
            .values(&expired_blacklisted)
            .execute(&db_connection)
            .unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&unexpired_blacklisted)
            .execute(&db_connection)
            .unwrap();

        assert!(clear_all_expired_refresh_tokens(&db_connection).unwrap() >= 1);

        assert!(!jwt::is_on_blacklist(&pretend_expired_token.to_string(), &db_connection).unwrap());
        assert!(jwt::is_on_blacklist(&unexpired_token.to_string(), &db_connection).unwrap());
    }
}
