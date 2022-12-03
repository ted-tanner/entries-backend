use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DataAccessor, DbConnection, DbThreadPool};
use crate::models::blacklisted_token::{BlacklistedToken, NewBlacklistedToken};
use crate::models::otp_attempts::OtpAttempts;
use crate::models::password_attempts::PasswordAttempts;
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;

pub struct Dao {
    db_connection: Option<Rc<RefCell<DbConnection>>>,
    db_thread_pool: DbThreadPool,
}

impl DataAccessor for Dao {
    fn new(db_thread_pool: DbThreadPool) -> Self {
        Self {
            db_connection: None,
            db_thread_pool,
        }
    }
}

impl Dao {
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
