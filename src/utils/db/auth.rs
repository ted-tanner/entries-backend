use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::definitions::*;
use crate::models::otp_attempts::OtpAttempts;
use crate::models::password_attempts::PasswordAttempts;
use crate::schema::blacklisted_tokens as token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

pub fn clear_all_expired_refresh_tokens(
    db_connection: &mut DbConnection,
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

pub fn clear_otp_verification_count(
    db_connection: &mut DbConnection,
) -> Result<usize, diesel::result::Error> {
    diesel::sql_query("TRUNCATE otp_attempts").execute(db_connection)
}

pub fn clear_password_attempt_count(
    db_connection: &mut DbConnection,
) -> Result<usize, diesel::result::Error> {
    diesel::sql_query("TRUNCATE password_attempts").execute(db_connection)
}

pub fn get_and_increment_otp_verification_count(
    db_connection: &mut DbConnection,
    user_id: Uuid,
) -> Result<i16, diesel::result::Error> {
    let query = "INSERT INTO otp_attempts \
                 (id, user_id, attempt_count) \
                 VALUES (DEFAULT, $1, 1) \
                 ON CONFLICT (user_id) DO UPDATE \
                 SET attempt_count = otp_attempts.attempt_count + 1 \
                 WHERE otp_attempts.user_id = $1 \
                 RETURNING *";

    let db_resp = diesel::sql_query(query)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .load::<OtpAttempts>(db_connection)?;

    Ok(db_resp[0].attempt_count)
}

pub fn get_and_increment_password_attempt_count(
    db_connection: &mut DbConnection,
    user_id: Uuid,
) -> Result<i16, diesel::result::Error> {
    let query = "INSERT INTO password_attempts \
                 (user_id, attempt_count) \
                 VALUES ($1, 1) \
                 ON CONFLICT (user_id) DO UPDATE \
                 SET attempt_count = password_attempts.attempt_count + 1 \
                 WHERE password_attempts.user_id = $1 \
                 RETURNING *";

    let db_resp = diesel::sql_query(query)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .load::<PasswordAttempts>(db_connection)?;

    Ok(db_resp[0].attempt_count)
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
    use crate::schema::otp_attempts as otp_attempts_fields;
    use crate::schema::otp_attempts::dsl::otp_attempts;
    use crate::schema::password_attempts as password_attempts_fields;
    use crate::schema::password_attempts::dsl::password_attempts;
    use crate::utils::auth_token;
    use crate::utils::db::user;

    #[actix_rt::test]
    async fn test_clear_all_expired_refresh_tokens() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
            currency: String::from("USD"),
        };

        user::create_user(&mut db_connection, &Json(new_user.clone())).unwrap();
        let user_id = user::get_user_by_email(&mut db_connection, &new_user.email)
            .unwrap()
            .id;

        let token_params = auth_token::TokenParams {
            user_id: &user_id,
            user_email: &new_user.email,
            user_currency: &new_user.currency,
        };

        let pretend_expired_token =
            auth_token::generate_refresh_token(token_params.clone()).unwrap();
        let unexpired_token = auth_token::generate_refresh_token(token_params).unwrap();

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
            .execute(&mut db_connection)
            .unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&unexpired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();

        assert!(clear_all_expired_refresh_tokens(&mut db_connection).unwrap() >= 1);

        assert!(!auth_token::is_on_blacklist(
            &pretend_expired_token.to_string(),
            &mut db_connection
        )
        .unwrap());
        assert!(
            auth_token::is_on_blacklist(&unexpired_token.to_string(), &mut db_connection).unwrap()
        );
    }

    #[actix_rt::test]
    async fn test_get_and_increment_otp_verification_count() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
            currency: String::from("USD"),
        };

        let user = user::create_user(&mut db_connection, &Json(new_user)).unwrap();

        let current_count =
            get_and_increment_otp_verification_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 1);

        let current_count =
            get_and_increment_otp_verification_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 2);

        let current_count =
            get_and_increment_otp_verification_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 3);
    }

    #[actix_rt::test]
    async fn test_get_and_increment_password_attempt_count() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd_opt(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            )
            .unwrap(),
            currency: String::from("USD"),
        };

        let user = user::create_user(&mut db_connection, &Json(new_user)).unwrap();

        let current_count =
            get_and_increment_password_attempt_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 1);

        let current_count =
            get_and_increment_password_attempt_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 2);

        let current_count =
            get_and_increment_password_attempt_count(&mut db_connection, user.id).unwrap();
        assert_eq!(current_count, 3);
    }

    #[ignore]
    #[actix_rt::test]
    async fn test_clear_otp_verification_count() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let mut user_ids = Vec::new();

        for _ in 0..3 {
            let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

            let new_user = InputUser {
                email: format!("test_user{}@test.com", &user_number),
                password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
                first_name: format!("Test-{}", &user_number),
                last_name: format!("User-{}", &user_number),
                date_of_birth: NaiveDate::from_ymd_opt(
                    rand::thread_rng().gen_range(1950..=2020),
                    rand::thread_rng().gen_range(1..=12),
                    rand::thread_rng().gen_range(1..=28),
                )
                .unwrap(),
                currency: String::from("USD"),
            };

            let user = user::create_user(&mut db_connection, &Json(new_user.clone())).unwrap();
            user_ids.push(user.id);

            for _ in 0..rand::thread_rng().gen_range::<u32, _>(1..4) {
                get_and_increment_otp_verification_count(&mut db_connection, user.id).unwrap();
            }
        }

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_ok());
        }

        clear_otp_verification_count(&mut db_connection).unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_err());
        }
    }

    #[ignore]
    #[actix_rt::test]
    async fn test_clear_password_attempt_count() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let mut db_connection = db_thread_pool.get().unwrap();

        let mut user_ids = Vec::new();

        for _ in 0..3 {
            let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

            let new_user = InputUser {
                email: format!("test_user{}@test.com", &user_number),
                password: String::from("OAgZbc6d&ARg*Wq#NPe3"),
                first_name: format!("Test-{}", &user_number),
                last_name: format!("User-{}", &user_number),
                date_of_birth: NaiveDate::from_ymd_opt(
                    rand::thread_rng().gen_range(1950..=2020),
                    rand::thread_rng().gen_range(1..=12),
                    rand::thread_rng().gen_range(1..=28),
                )
                .unwrap(),
                currency: String::from("USD"),
            };

            let user = user::create_user(&mut db_connection, &Json(new_user.clone())).unwrap();
            user_ids.push(user.id);

            for _ in 0..rand::thread_rng().gen_range::<u32, _>(1..4) {
                get_and_increment_password_attempt_count(&mut db_connection, user.id).unwrap();
            }
        }

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_pass_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_ok());
        }

        clear_password_attempt_count(&mut db_connection).unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_pass_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_err());
        }
    }
}
