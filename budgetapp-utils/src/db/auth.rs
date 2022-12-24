use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbConnection, DbThreadPool};
use crate::models::blacklisted_token::{BlacklistedToken, NewBlacklistedToken};
use crate::models::otp_attempts::{NewOtpAttempts, OtpAttempts};
use crate::models::password_attempts::{NewPasswordAttempts, PasswordAttempts};
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
use crate::schema::otp_attempts as otp_attempt_fields;
use crate::schema::otp_attempts::dsl::otp_attempts;
use crate::schema::password_attempts as password_attempt_fields;
use crate::schema::password_attempts::dsl::password_attempts;

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
        token_expiration_time: SystemTime,
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
        Ok(diesel::delete(
            blacklisted_tokens
                .filter(blacklisted_token_fields::token_expiration_time.lt(SystemTime::now())),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn clear_otp_verification_count(
        &mut self,
        attempts_lifetime: Duration,
    ) -> Result<usize, DaoError> {
        let expiration_cut_off = SystemTime::now() - attempts_lifetime;

        Ok(diesel::delete(
            otp_attempts.filter(otp_attempt_fields::expiration_time.lt(expiration_cut_off)),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn clear_password_attempt_count(
        &mut self,
        attempts_lifetime: Duration,
    ) -> Result<usize, DaoError> {
        let expiration_cut_off = SystemTime::now() - attempts_lifetime;

        Ok(diesel::delete(
            password_attempts
                .filter(password_attempt_fields::expiration_time.lt(expiration_cut_off)),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_and_increment_otp_verification_count(
        &mut self,
        user_id: Uuid,
        attempts_lifetime: Duration,
    ) -> Result<OtpAttempts, DaoError> {
        let expiration_time = SystemTime::now() + attempts_lifetime;

        let new_attempt = NewOtpAttempts {
            user_id,
            attempt_count: 1,
            expiration_time,
        };

        Ok(dsl::insert_into(otp_attempts)
            .values(&new_attempt)
            .on_conflict(otp_attempt_fields::user_id)
            .do_update()
            .set(otp_attempt_fields::attempt_count.eq(otp_attempt_fields::attempt_count + 1))
            .get_result::<OtpAttempts>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_and_increment_password_attempt_count(
        &mut self,
        user_id: Uuid,
        attempts_lifetime: Duration,
    ) -> Result<PasswordAttempts, DaoError> {
        let expiration_time = SystemTime::now() + attempts_lifetime;

        let new_attempt = NewPasswordAttempts {
            user_id,
            attempt_count: 1,
            expiration_time,
        };

        Ok(dsl::insert_into(password_attempts)
            .values(&new_attempt)
            .on_conflict(password_attempt_fields::user_id)
            .do_update()
            .set(
                password_attempt_fields::attempt_count
                    .eq(password_attempt_fields::attempt_count + 1),
            )
            .get_result::<PasswordAttempts>(&mut *(self.get_connection()?).borrow_mut())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use diesel::{dsl, RunQueryDsl};
    use rand::prelude::*;
    use std::time::{Duration, SystemTime};

    use crate::auth_token;
    use crate::db::user;
    use crate::models::blacklisted_token::NewBlacklistedToken;
    use crate::password_hasher;
    use crate::request_io::InputUser;
    use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
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
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
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

        let expired_blacklisted = NewBlacklistedToken {
            token: &pretend_expired_token.to_string(),
            user_id,
            token_expiration_time: SystemTime::now() - Duration::from_secs(3600),
        };

        let unexpired_blacklisted = NewBlacklistedToken {
            token: &unexpired_token.to_string(),
            user_id,
            token_expiration_time: SystemTime::now() + Duration::from_secs(3600),
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
            !auth_token::is_on_blacklist(&pretend_expired_token.to_string(), &mut dao).unwrap()
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
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
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

        let attempts = dao
            .get_and_increment_otp_verification_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 1);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));

        let attempts = dao
            .get_and_increment_otp_verification_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 2);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));

        let attempts = dao
            .get_and_increment_otp_verification_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 3);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));
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
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
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

        let attempts = dao
            .get_and_increment_password_attempt_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 1);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));

        let attempts = dao
            .get_and_increment_password_attempt_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 2);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));

        let attempts = dao
            .get_and_increment_password_attempt_count(user.id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(attempts.attempt_count, 3);
        assert_eq!(attempts.user_id, user.id);
        assert!(attempts.expiration_time > SystemTime::now());
        assert!(attempts.expiration_time < SystemTime::now() + Duration::from_secs(2));
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
                date_of_birth: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
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
                dao.get_and_increment_otp_verification_count(user.id, Duration::from_secs(10))
                    .unwrap();
            }
        }

        let mut db_connection = db_thread_pool.get().unwrap();

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempt_fields::user_id.eq(user_id))
                .first::<OtpAttempts>(&mut db_connection);
            assert!(user_otp_attempts.is_ok());
        }

        std::thread::sleep(Duration::from_millis(2));
        dao.clear_otp_verification_count(Duration::from_millis(1))
            .unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_otp_attempts = otp_attempts
                .filter(otp_attempt_fields::user_id.eq(user_id))
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
                date_of_birth: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
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
                dao.get_and_increment_password_attempt_count(user.id, Duration::from_secs(10))
                    .unwrap();
            }
        }

        let mut db_connection = db_thread_pool.get().unwrap();

        // Ensure rows are in the table before clearing
        for user_id in user_ids.clone() {
            let user_pass_attempts = password_attempts
                .filter(password_attempt_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_ok());
        }

        std::thread::sleep(Duration::from_millis(2));
        dao.clear_password_attempt_count(Duration::from_millis(1))
            .unwrap();

        // Ensure rows have been removed
        for user_id in user_ids {
            let user_pass_attempts = password_attempts
                .filter(password_attempt_fields::user_id.eq(user_id))
                .first::<PasswordAttempts>(&mut db_connection);
            assert!(user_pass_attempts.is_err());
        }
    }
}
