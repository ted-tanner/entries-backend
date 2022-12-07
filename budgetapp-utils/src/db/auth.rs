use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbConnection, DbThreadPool};
use crate::models::blacklisted_token::{BlacklistedToken, NewBlacklistedToken};
use crate::models::otp_attempts::OtpAttempts;
use crate::models::password_attempts::PasswordAttempts;
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

pub struct Dao {
    db_connection: Option<Rc<RefCell<DbConnection>>>,
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_connection: None,
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    fn get_connection(&mut self) -> Result<Rc<RefCell<DbConnection>>, DaoError> {
        if let Some(conn) = &self.db_connection {
            Ok(Rc::clone(conn))
        } else {
            let conn = Rc::new(RefCell::new(self.db_thread_pool.get()?));
            self.db_connection = Some(Rc::clone(&conn));
            Ok(conn)
        }
    }

    pub fn create_blacklisted_token(
        &mut self,
        token: &str,
        user_id: Uuid,
        token_expiration_time: i64,
    ) -> Result<(), DaoError> {
        let blacklisted_token = NewBlacklistedToken {
            token,
            user_id,
            token_expiration_time,
        };

        dsl::insert_into(blacklisted_tokens)
            .values(&blacklisted_token)
            .get_result::<BlacklistedToken>(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(())
    }

    pub fn check_is_token_on_blacklist(&mut self, token: &str) -> Result<bool, DaoError> {
        let count = blacklisted_tokens
            .filter(blacklisted_token_fields::token.eq(token))
            .count()
            .get_result::<i64>(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(count > 0)
    }

    pub fn clear_all_expired_refresh_tokens(&mut self) -> Result<usize, DaoError> {
        // Add two minutes to current time to prevent slight clock differences/inaccuracies from
        // opening a window for an attacker to use an expired refresh token
        let current_unix_epoch: i64 = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs()
            + 120)
            .try_into()
            .expect("Seconds since Unix Epoch is too big to be stored in a signed 64-bit integer");

        Ok(diesel::delete(
            blacklisted_tokens
                .filter(blacklisted_token_fields::token_expiration_time.lt(current_unix_epoch)),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn clear_otp_verification_count(&mut self) -> Result<usize, DaoError> {
        Ok(diesel::sql_query("TRUNCATE otp_attempts")
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn clear_password_attempt_count(&mut self) -> Result<usize, DaoError> {
        Ok(diesel::sql_query("TRUNCATE password_attempts")
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_and_increment_otp_verification_count(
        &mut self,
        user_id: Uuid,
    ) -> Result<i16, DaoError> {
        let query = "INSERT INTO otp_attempts \
                     (id, user_id, attempt_count) \
                     VALUES (DEFAULT, $1, 1) \
                     ON CONFLICT (user_id) DO UPDATE \
                     SET attempt_count = otp_attempts.attempt_count + 1 \
                     WHERE otp_attempts.user_id = $1 \
                     RETURNING *";

        let db_resp = diesel::sql_query(query)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .load::<OtpAttempts>(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(db_resp[0].attempt_count)
    }

    pub fn get_and_increment_password_attempt_count(
        &mut self,
        user_id: Uuid,
    ) -> Result<i16, DaoError> {
        let query = "INSERT INTO password_attempts \
                     (user_id, attempt_count) \
                     VALUES ($1, 1) \
                     ON CONFLICT (user_id) DO UPDATE \
                     SET attempt_count = password_attempts.attempt_count + 1 \
                     WHERE password_attempts.user_id = $1 \
                     RETURNING *";

        let db_resp = diesel::sql_query(query)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .load::<PasswordAttempts>(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(db_resp[0].attempt_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::NaiveDate;
    use diesel::{dsl, RunQueryDsl};
    use rand::prelude::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::auth_token;
    use crate::db::user;
    use crate::models::blacklisted_token::NewBlacklistedToken;
    use crate::password_hasher;
    use crate::request_io::InputUser;
    use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
    use crate::schema::otp_attempts as otp_attempts_fields;
    use crate::schema::otp_attempts::dsl::otp_attempts;
    use crate::schema::password_attempts as password_attempts_fields;
    use crate::schema::password_attempts::dsl::password_attempts;
    use crate::test_env;

    #[test]
    fn test_clear_all_expired_refresh_tokens() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

        let hash_params = password_hasher::HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let mut user_dao = user::Dao::new(db_thread_pool);

        user_dao
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let user_id = user_dao.get_user_by_email(&new_user.email).unwrap().id;

        let token_params = auth_token::TokenParams {
            user_id: &user_id,
            user_email: &new_user.email,
            user_currency: &new_user.currency,
        };

        let pretend_expired_token = auth_token::generate_refresh_token(
            &token_params,
            Duration::from_secs(5),
            vec![32, 4, 23, 53].as_slice(),
        )
        .unwrap();
        let unexpired_token = auth_token::generate_refresh_token(
            &token_params,
            Duration::from_secs(5),
            vec![32, 4, 23, 53].as_slice(),
        )
        .unwrap();

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

        let mut db_connection = db_thread_pool.get().unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&expired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();
        dsl::insert_into(blacklisted_tokens)
            .values(&unexpired_blacklisted)
            .execute(&mut db_connection)
            .unwrap();

        assert!(dao.clear_all_expired_refresh_tokens().unwrap() >= 1);

        assert!(
            !auth_token::is_on_blacklist(&pretend_expired_token.to_string(), &mut dao,).unwrap()
        );
        assert!(auth_token::is_on_blacklist(&unexpired_token.to_string(), &mut dao).unwrap());
    }

    #[test]
    fn test_get_and_increment_otp_verification_count() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

        let hash_params = password_hasher::HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let user = user::Dao::new(db_thread_pool)
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let current_count = dao
            .get_and_increment_otp_verification_count(user.id)
            .unwrap();
        assert_eq!(current_count, 1);

        let current_count = dao
            .get_and_increment_otp_verification_count(user.id)
            .unwrap();
        assert_eq!(current_count, 2);

        let current_count = dao
            .get_and_increment_otp_verification_count(user.id)
            .unwrap();
        assert_eq!(current_count, 3);
    }

    #[test]
    fn test_get_and_increment_password_attempt_count() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

        let hash_params = password_hasher::HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let user = user::Dao::new(db_thread_pool)
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let current_count = dao
            .get_and_increment_password_attempt_count(user.id)
            .unwrap();
        assert_eq!(current_count, 1);

        let current_count = dao
            .get_and_increment_password_attempt_count(user.id)
            .unwrap();
        assert_eq!(current_count, 2);

        let current_count = dao
            .get_and_increment_password_attempt_count(user.id)
            .unwrap();
        assert_eq!(current_count, 3);
    }

    #[ignore]
    #[test]
    fn test_clear_otp_verification_count() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

            let hash_params = password_hasher::HashParams {
                salt_len: 16,
                hash_len: 32,
                hash_iterations: 2,
                hash_mem_size_kib: 128,
                hash_lanes: 2,
            };

            let user = user::Dao::new(db_thread_pool)
                .create_user(
                    &new_user,
                    &hash_params,
                    vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
                )
                .unwrap();

            user_ids.push(user.id);

            for _ in 0..rand::thread_rng().gen_range::<u32, _>(1..4) {
                dao.get_and_increment_otp_verification_count(user.id)
                    .unwrap();
            }
        }

        let mut db_connection = db_thread_pool.get().unwrap();

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_ok());
        }

        dao.clear_otp_verification_count().unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempts_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_err());
        }
    }

    #[ignore]
    #[test]
    fn test_clear_password_attempt_count() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

            let hash_params = password_hasher::HashParams {
                salt_len: 16,
                hash_len: 32,
                hash_iterations: 2,
                hash_mem_size_kib: 128,
                hash_lanes: 2,
            };

            let user = user::Dao::new(db_thread_pool)
                .create_user(
                    &new_user,
                    &hash_params,
                    vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
                )
                .unwrap();

            user_ids.push(user.id);

            for _ in 0..rand::thread_rng().gen_range::<u32, _>(1..4) {
                dao.get_and_increment_password_attempt_count(user.id)
                    .unwrap();
            }
        }

        let mut db_connection = db_thread_pool.get().unwrap();

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_pass_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_ok());
        }

        dao.clear_password_attempt_count().unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_pass_attempts = password_attempts
                .filter(password_attempts_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_err());
        }
    }
}
