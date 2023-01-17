use diesel::{
    dsl, sql_query, sql_types, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use std::collections::HashSet;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::buddy_relationship::{BuddyRelationship, NewBuddyRelationship};
use crate::models::buddy_request::{BuddyRequest, NewBuddyRequest};
use crate::models::user::{NewUser, User};
use crate::models::user_deletion_request::{NewUserDeletionRequest, UserDeletionRequest};
use crate::models::user_notification::{NewUserNotification, UserNotification};
use crate::models::user_tombstone::{NewUserTombstone, UserTombstone};
use crate::password_hasher;
use crate::request_io::{InputEditUser, InputUser};
use crate::schema::buddy_relationships as buddy_relationship_fields;
use crate::schema::buddy_relationships::dsl::buddy_relationships;
use crate::schema::buddy_requests as buddy_request_fields;
use crate::schema::buddy_requests::dsl::buddy_requests;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::user_budgets as user_budget_fields;
use crate::schema::user_budgets::dsl::user_budgets;
use crate::schema::user_deletion_requests as user_deletion_request_fields;
use crate::schema::user_deletion_requests::dsl::user_deletion_requests;
use crate::schema::user_notifications as user_notification_fields;
use crate::schema::user_notifications::dsl::user_notifications;
use crate::schema::user_tombstones as user_tombstone_fields;
use crate::schema::user_tombstones::dsl::user_tombstones;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn get_user_by_id(&mut self, user_id: Uuid) -> Result<User, DaoError> {
        Ok(users
            .find(user_id)
            .first::<User>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_user_by_email(&mut self, user_email: &str) -> Result<User, DaoError> {
        Ok(users
            .filter(user_fields::email.eq(user_email.to_lowercase()))
            .first::<User>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn create_user(
        &mut self,
        user_data: &InputUser,
        hash_params: &password_hasher::HashParams,
        hashing_secret_key: &[u8],
    ) -> Result<User, DaoError> {
        let hashed_password =
            password_hasher::hash_password(&user_data.password, hash_params, hashing_secret_key);
        let current_time = SystemTime::now();

        let new_user = NewUser {
            id: Uuid::new_v4(),
            email: &user_data.email.to_lowercase(),
            password_hash: &hashed_password,
            first_name: &user_data.first_name,
            last_name: &user_data.last_name,
            date_of_birth: user_data.date_of_birth,
            currency: &user_data.currency,
            last_token_refresh_timestamp: current_time,
            modified_timestamp: current_time,
            created_timestamp: current_time,
        };

        Ok(dsl::insert_into(users)
            .values(&new_user)
            .get_result::<User>(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn set_last_token_refresh_now(&mut self, user_id: Uuid) -> Result<usize, DaoError> {
        Ok(dsl::update(users.find(user_id))
            .set(user_fields::last_token_refresh_timestamp.eq(SystemTime::now()))
            .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn edit_user(
        &mut self,
        user_id: Uuid,
        edited_user_data: &InputEditUser,
    ) -> Result<usize, DaoError> {
        Ok(dsl::update(users.find(user_id))
            .set((
                user_fields::modified_timestamp.eq(SystemTime::now()),
                user_fields::first_name.eq(&edited_user_data.first_name),
                user_fields::last_name.eq(&edited_user_data.last_name),
                user_fields::date_of_birth.eq(&edited_user_data.date_of_birth),
                user_fields::currency.eq(&edited_user_data.currency),
            ))
            .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn change_password(
        &mut self,
        user_id: Uuid,
        new_password: &str,
        hash_params: &password_hasher::HashParams,
        hashing_secret_key: &[u8],
    ) -> Result<(), DaoError> {
        let hashed_password =
            password_hasher::hash_password(new_password, hash_params, hashing_secret_key);

        dsl::update(users.find(user_id))
            .set(user_fields::password_hash.eq(hashed_password))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn send_buddy_request(
        &mut self,
        recipient_user_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<BuddyRequest, DaoError> {
        let request = NewBuddyRequest {
            id: Uuid::new_v4(),
            recipient_user_id,
            sender_user_id,
            accepted: false,
            created_timestamp: SystemTime::now(),
            accepted_declined_timestamp: None,
        };

        Ok(dsl::insert_into(buddy_requests)
            .values(&request)
            .on_conflict((
                buddy_request_fields::recipient_user_id,
                buddy_request_fields::sender_user_id,
            ))
            .do_update()
            .set((
                buddy_request_fields::accepted.eq(false),
                buddy_request_fields::created_timestamp.eq(SystemTime::now()),
                buddy_request_fields::accepted_declined_timestamp.eq(None::<SystemTime>),
            ))
            .get_result::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn delete_buddy_request(
        &mut self,
        request_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            buddy_requests
                .find(request_id)
                .filter(buddy_request_fields::sender_user_id.eq(sender_user_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn delete_buddy_request_notification(
        &mut self,
        request_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            user_notifications.filter(
                dsl::sql::<sql_types::Bool>("payload->>'buddy_request_id' = '$1'")
                    .bind::<sql_types::Uuid, _>(request_id),
            ),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn mark_buddy_request_accepted(
        &mut self,
        request_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<BuddyRequest, DaoError> {
        Ok(diesel::update(
            buddy_requests
                .find(request_id)
                .filter(buddy_request_fields::recipient_user_id.eq(recipient_user_id)),
        )
        .set((
            buddy_request_fields::accepted.eq(true),
            buddy_request_fields::accepted_declined_timestamp.eq(SystemTime::now()),
        ))
        .get_result(&mut self.db_thread_pool.get()?)?)
    }

    pub fn mark_buddy_request_declined(
        &mut self,
        request_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::update(
            buddy_requests
                .find(request_id)
                .filter(buddy_request_fields::recipient_user_id.eq(recipient_user_id)),
        )
        .set((
            buddy_request_fields::accepted.eq(false),
            buddy_request_fields::accepted_declined_timestamp.eq(SystemTime::now()),
        ))
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_all_pending_buddy_requests_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(user_id))
            .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
            .order(buddy_request_fields::created_timestamp.asc())
            .load::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_all_pending_buddy_requests_made_by_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(user_id))
            .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
            .order(buddy_request_fields::created_timestamp.asc())
            .load::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_buddy_request(
        &mut self,
        request_id: Uuid,
        user_id: Uuid,
    ) -> Result<BuddyRequest, DaoError> {
        Ok(buddy_requests
            .find(request_id)
            .filter(
                buddy_request_fields::sender_user_id
                    .eq(user_id)
                    .or(buddy_request_fields::recipient_user_id.eq(user_id)),
            )
            .first::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn create_buddy_relationship(
        &mut self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<BuddyRelationship, DaoError> {
        let current_time = SystemTime::now();

        let relationship = NewBuddyRelationship {
            created_timestamp: current_time,
            user1_id,
            user2_id,
        };

        Ok(dsl::insert_into(buddy_relationships)
            .values(&relationship)
            .get_result::<BuddyRelationship>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn delete_buddy_relationship(
        &mut self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            buddy_relationships.filter(
                buddy_relationship_fields::user1_id
                    .eq(user1_id)
                    .and(buddy_relationship_fields::user2_id.eq(user2_id))
                    .or(buddy_relationship_fields::user1_id
                        .eq(user2_id)
                        .and(buddy_relationship_fields::user2_id.eq(user1_id))),
            ),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_buddies(&mut self, user_id: Uuid) -> Result<Vec<User>, DaoError> {
        let query = "SELECT u.* FROM users AS u, buddy_relationships AS br \
                     WHERE (br.user1_id = $1 AND u.id = br.user2_id) \
                     OR (br.user2_id = $1 AND u.id = br.user1_id) \
                     ORDER BY br.created_timestamp";

        Ok(sql_query(query)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .load(&mut self.db_thread_pool.get()?)?)
    }

    pub fn check_are_buddies(&mut self, user1_id: Uuid, user2_id: Uuid) -> Result<bool, DaoError> {
        Ok(dsl::select(dsl::exists(
            buddy_relationships.filter(
                buddy_relationship_fields::user1_id
                    .eq(user1_id)
                    .and(buddy_relationship_fields::user2_id.eq(user2_id))
                    .or(buddy_relationship_fields::user1_id
                        .eq(user2_id)
                        .and(buddy_relationship_fields::user2_id.eq(user1_id))),
            ),
        ))
        .get_result(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn create_notification(
        &mut self,
        user_id: Uuid,
        notification_type: &str,
        payload: &serde_json::Value,
    ) -> Result<UserNotification, DaoError> {
        let new_notification = NewUserNotification {
            id: Uuid::new_v4(),
            user_id,
            is_pristine: true,
            is_unread: true,
            notification_type,
            payload,
            modified_timestamp: SystemTime::now(),
            created_timestamp: SystemTime::now(),
        };

        Ok(dsl::insert_into(user_notifications)
            .values(&new_notification)
            .get_result::<UserNotification>(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn get_unread_notifications(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<UserNotification>, DaoError> {
        Ok(user_notifications
            .filter(user_notification_fields::user_id.eq(user_id))
            .order_by(user_notification_fields::created_timestamp.asc())
            .get_results::<UserNotification>(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn mark_notifications_read(
        &mut self,
        notification_ids: HashSet<Uuid>,
        user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(dsl::update(
            user_notifications
                .filter(user_notification_fields::id.eq_any(notification_ids))
                .filter(user_notification_fields::user_id.eq(user_id)),
        )
        .set((
            user_notification_fields::is_unread.eq(false),
            user_notification_fields::modified_timestamp.eq(SystemTime::now()),
        ))
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn mark_notification_touched(
        &mut self,
        notification_id: Uuid,
        user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(dsl::update(
            user_notifications
                .find(notification_id)
                .filter(user_notification_fields::user_id.eq(user_id)),
        )
        .set((
            user_notification_fields::is_pristine.eq(false),
            user_notification_fields::is_unread.eq(false),
            user_notification_fields::modified_timestamp.eq(SystemTime::now()),
        ))
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn clear_old_notifications(&mut self, max_age: Duration) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            user_notifications
                .filter(
                    user_notification_fields::modified_timestamp.lt(SystemTime::now() - max_age),
                )
                .filter(user_notification_fields::is_unread.eq(false)),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn initiate_user_deletion(
        &mut self,
        user_id: Uuid,
        time_until_deletion: Duration,
    ) -> Result<usize, DaoError> {
        let new_request = NewUserDeletionRequest {
            user_id,
            deletion_request_time: SystemTime::now(),
            ready_for_deletion_time: SystemTime::now() + time_until_deletion,
        };

        Ok(dsl::insert_into(user_deletion_requests)
            .values(&new_request)
            .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn cancel_user_deletion(&mut self, user_id: Uuid) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            user_deletion_requests.filter(user_deletion_request_fields::user_id.eq(user_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn delete_user(&mut self, request: &UserDeletionRequest) -> Result<usize, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let new_tombstone = NewUserTombstone {
            user_id: request.user_id,
            deletion_request_time: request.deletion_request_time,
            deletion_timestamp: SystemTime::now(),
        };

        dsl::insert_into(user_tombstones)
            .values(&new_tombstone)
            .execute(&mut db_connection)?;

        diesel::delete(budgets)
            .filter(
                user_budgets
                    .filter(user_budget_fields::user_id.eq(request.user_id))
                    .filter(budget_fields::id.eq(user_budget_fields::budget_id))
                    .count()
                    .single_value()
                    .eq(1),
            )
            .execute(&mut db_connection)?;

        let delete_user_res =
            diesel::delete(users.find(request.user_id)).execute(&mut db_connection)?;

        // Do this last. If there is an error before this point, the request will still be
        // present.
        //
        // NOTE: Future changes to the error handling of a failed deletion may necessitate the
        //       deletion of the request FIRST rather than last.
        diesel::delete(
            user_deletion_requests
                .filter(user_deletion_request_fields::user_id.eq(request.user_id)),
        )
        .execute(&mut db_connection)?;

        Ok(delete_user_res)
    }

    // TODO: Test
    pub fn get_all_users_ready_for_deletion(
        &mut self,
    ) -> Result<Vec<UserDeletionRequest>, DaoError> {
        Ok(user_deletion_requests
            .filter(user_deletion_request_fields::ready_for_deletion_time.lt(SystemTime::now()))
            .get_results(&mut self.db_thread_pool.get()?)?)
    }

    // TODO: Test
    pub fn get_user_tombstone(&mut self, user_id: Uuid) -> Result<UserTombstone, DaoError> {
        Ok(user_tombstones
            .filter(user_tombstone_fields::user_id.eq(user_id))
            .first::<UserTombstone>(&mut self.db_thread_pool.get()?)?)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use rand::prelude::*;
    use std::time::Duration;

    use crate::models::buddy_relationship::BuddyRelationship;
    use crate::models::buddy_request::BuddyRequest;
    use crate::schema::buddy_requests as buddy_request_fields;
    use crate::schema::buddy_requests::dsl::buddy_requests;
    use crate::test_env;

    pub fn generate_user() -> Result<User, DaoError> {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", user_number),
            password: String::from("g&eWi3#oIKDW%cTu*5*2"),
            first_name: format!("Test-{}", user_number),
            last_name: format!("User-{}", user_number),
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

        Dao::new(db_thread_pool).create_user(
            &new_user,
            &hash_params,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
    }

    #[test]
    fn test_create_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "X$KC3%s&L91m!bVA*@Iu";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
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

        dao.create_user(
            &new_user,
            &hash_params,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let created_user = users
            .filter(user_fields::email.eq(&new_user.email.to_lowercase()))
            .first::<User>(&mut db_connection)
            .unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[test]
    fn test_get_user_by_email() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        const PASSWORD: &str = "Uo^Z56o%f#@8Ub#I9D&f";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let user_email = format!("test_user{}@test.com", &user_number);
        let new_user = InputUser {
            email: user_email.clone(),
            password: PASSWORD.to_string(),
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

        dao.create_user(
            &new_user,
            &hash_params,
            vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
        )
        .unwrap();

        let created_user = dao.get_user_by_email(&user_email).unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[test]
    fn test_get_user_by_id() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        const PASSWORD: &str = "Uo^Z56o%f#@8Ub#I9D&f";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
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

        let user_id = dao
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap()
            .id;

        let created_user = dao.get_user_by_id(user_id).unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[test]
    fn test_edit_user_one_field() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        const PASSWORD: &str = "C4R1pUr2E2fG5qKPT&&s";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
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

        let user_before = dao
            .create_user(&new_user, &hash_params, vec![38, 23, 5, 1, 7].as_slice())
            .unwrap();

        let user_edits = InputEditUser {
            first_name: String::from("Edited Name"),
            last_name: user_before.last_name.clone(),
            date_of_birth: user_before.date_of_birth,
            currency: user_before.currency.clone(),
        };

        dao.edit_user(user_before.id, &user_edits).unwrap();

        let user_after = dao.get_user_by_id(user_before.id).unwrap();

        assert_eq!(&user_after.email, &user_before.email);
        assert_eq!(&user_after.last_name, &user_before.last_name);
        assert_eq!(&user_after.date_of_birth, &user_before.date_of_birth);
        assert_eq!(&user_after.currency, &user_before.currency);
        assert_eq!(&user_after.password_hash, &user_before.password_hash);
        assert_eq!(&user_after.first_name, &user_edits.first_name);
    }

    #[test]
    fn test_edit_user_all_fields() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        const PASSWORD: &str = "C4R1pUr2E2fG5qKPT&&s";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
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

        let user_before = dao
            .create_user(&new_user, &hash_params, vec![38, 23, 5, 1, 7].as_slice())
            .unwrap();

        let user_edits = InputEditUser {
            first_name: String::from("Edited"),
            last_name: String::from("Name"),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            currency: String::from("DOP"),
        };

        dao.edit_user(user_before.id, &user_edits).unwrap();

        let user_after = dao.get_user_by_id(user_before.id).unwrap();

        assert_eq!(&user_after.password_hash, &user_before.password_hash);
        assert_eq!(&user_after.email, &new_user.email);
        assert_eq!(&user_after.first_name, &user_edits.first_name);
        assert_eq!(&user_after.last_name, &user_edits.last_name);
        assert_eq!(&user_after.date_of_birth, &user_edits.date_of_birth);
        assert_eq!(&user_after.currency, &user_edits.currency);
    }

    #[test]
    fn test_change_password() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        const ORIGINAL_PASSWORD: &str = "Eq&6T@Vyz54O%DoX$";
        const UPDATED_PASSWORD: &str = "P*%OaTMaMl^Uzft^$82Qn";

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: ORIGINAL_PASSWORD.to_string(),
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

        let secret_key = vec![38, 23, 5, 1, 7];
        let user_id = dao
            .create_user(&new_user, &hash_params, secret_key.as_slice())
            .unwrap()
            .id;

        let original_password_saved_hash = users
            .find(user_id)
            .select(user_fields::password_hash)
            .get_result::<String>(&mut db_connection)
            .unwrap();

        assert!(password_hasher::verify_hash(
            ORIGINAL_PASSWORD,
            &original_password_saved_hash,
            secret_key.as_slice(),
        ));

        dao.change_password(
            user_id,
            UPDATED_PASSWORD,
            &hash_params,
            secret_key.as_slice(),
        )
        .unwrap();

        let updated_password_saved_hash = users
            .find(user_id)
            .select(user_fields::password_hash)
            .get_result::<String>(&mut db_connection)
            .unwrap();

        assert_ne!(original_password_saved_hash, updated_password_saved_hash);
        assert!(password_hasher::verify_hash(
            UPDATED_PASSWORD,
            &updated_password_saved_hash,
            secret_key.as_slice(),
        ));
    }

    #[test]
    fn test_send_buddy_request() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        let created_buddy_request = dao
            .send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        assert_eq!(created_buddy_request.recipient_user_id, created_user2.id);
        assert_eq!(created_buddy_request.sender_user_id, created_user1.id);
        assert!(!created_buddy_request.accepted);
        assert!(created_buddy_request.created_timestamp < SystemTime::now());
        assert_eq!(created_buddy_request.accepted_declined_timestamp, None);
    }

    #[test]
    fn test_delete_buddy_request() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        dao.delete_buddy_request(created_buddy_requests[0].id, created_user1.id)
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);
    }

    #[test]
    fn test_mark_buddy_request_accepted() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let returned_buddy_request = dao
            .mark_buddy_request_accepted(created_buddy_requests[0].id, created_user2.id)
            .unwrap();

        assert_eq!(returned_buddy_request.recipient_user_id, created_user2.id);
        assert_eq!(returned_buddy_request.sender_user_id, created_user1.id);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(created_buddy_requests[0].sender_user_id, created_user1.id);

        assert!(created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0].created_timestamp < SystemTime::now());
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                < SystemTime::now()
        );
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_buddy_requests[0].created_timestamp
        );
    }

    #[test]
    fn test_mark_buddy_request_declined() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let returned_buddy_request_count = dao
            .mark_buddy_request_declined(created_buddy_requests[0].id, created_user2.id)
            .unwrap();

        assert_eq!(returned_buddy_request_count, 1);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(created_buddy_requests[0].sender_user_id, created_user1.id);

        assert!(!created_buddy_requests[0].accepted);

        assert!(created_buddy_requests[0].created_timestamp < SystemTime::now());
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                < SystemTime::now()
        );
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_buddy_requests[0].created_timestamp
        );
    }

    #[test]
    fn test_get_all_pending_buddy_requests_for_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();
        let created_user3 = generate_user().unwrap();

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();
        dao.send_buddy_request(created_user2.id, created_user3.id)
            .unwrap();

        let requests = dao
            .get_all_pending_buddy_requests_for_user(created_user1.id)
            .unwrap();

        assert_eq!(requests.len(), 0);

        let requests = dao
            .get_all_pending_buddy_requests_for_user(created_user3.id)
            .unwrap();

        assert_eq!(requests.len(), 0);

        let requests = dao
            .get_all_pending_buddy_requests_for_user(created_user2.id)
            .unwrap();

        assert_eq!(requests.len(), 2);

        assert_eq!(requests[0].recipient_user_id, created_user2.id);
        assert_eq!(requests[0].sender_user_id, created_user1.id);
        assert!(!requests[0].accepted);

        assert!(requests[0].created_timestamp < SystemTime::now());
        assert!(requests[0].accepted_declined_timestamp.is_none());

        assert_eq!(requests[1].recipient_user_id, created_user2.id);
        assert_eq!(requests[1].sender_user_id, created_user3.id);
        assert!(!requests[1].accepted);

        assert!(requests[1].created_timestamp < SystemTime::now());
        assert!(requests[1].accepted_declined_timestamp.is_none());

        dao.mark_buddy_request_accepted(requests[0].id, created_user2.id)
            .unwrap();

        let requests = dao
            .get_all_pending_buddy_requests_for_user(created_user2.id)
            .unwrap();

        assert_eq!(requests.len(), 1);

        assert_eq!(requests[0].recipient_user_id, created_user2.id);
        assert_eq!(requests[0].sender_user_id, created_user3.id);
        assert!(!requests[0].accepted);

        assert!(requests[0].created_timestamp < SystemTime::now());
        assert!(requests[0].accepted_declined_timestamp.is_none());
    }

    #[test]
    fn test_get_all_pending_buddy_requests_made_by_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();
        let created_user3 = generate_user().unwrap();

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        dao.send_buddy_request(created_user3.id, created_user1.id)
            .unwrap();

        let requests = dao
            .get_all_pending_buddy_requests_made_by_user(created_user2.id)
            .unwrap();

        assert_eq!(requests.len(), 0);

        let requests = dao
            .get_all_pending_buddy_requests_made_by_user(created_user3.id)
            .unwrap();

        assert_eq!(requests.len(), 0);

        let requests = dao
            .get_all_pending_buddy_requests_made_by_user(created_user1.id)
            .unwrap();

        assert_eq!(requests.len(), 2);

        assert_eq!(requests[0].recipient_user_id, created_user2.id);
        assert_eq!(requests[0].sender_user_id, created_user1.id);
        assert!(!requests[0].accepted);

        assert!(requests[0].created_timestamp < SystemTime::now());
        assert!(requests[0].accepted_declined_timestamp.is_none());

        assert_eq!(requests[1].recipient_user_id, created_user3.id);
        assert_eq!(requests[1].sender_user_id, created_user1.id);
        assert!(!requests[1].accepted);

        assert!(requests[1].created_timestamp < SystemTime::now());
        assert!(requests[1].accepted_declined_timestamp.is_none());

        dao.mark_buddy_request_accepted(requests[0].id, created_user2.id)
            .unwrap();

        let requests = dao
            .get_all_pending_buddy_requests_made_by_user(created_user1.id)
            .unwrap();

        assert_eq!(requests.len(), 1);

        assert_eq!(requests[0].recipient_user_id, created_user3.id);
        assert_eq!(requests[0].sender_user_id, created_user1.id);
        assert!(!requests[0].accepted);

        assert!(requests[0].created_timestamp < SystemTime::now());
        assert!(requests[0].accepted_declined_timestamp.is_none());
    }

    #[test]
    fn test_get_buddy_request() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        dao.send_buddy_request(created_user2.id, created_user1.id)
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&mut db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        dao.mark_buddy_request_accepted(created_buddy_requests[0].id, created_user2.id)
            .unwrap();

        let request = dao
            .get_buddy_request(created_buddy_requests[0].id, created_user1.id)
            .unwrap();

        assert_eq!(request.recipient_user_id, created_user2.id);
        assert_eq!(request.sender_user_id, created_user1.id);
        assert!(request.accepted);

        assert!(request.created_timestamp < SystemTime::now());
        assert!(request.accepted_declined_timestamp.unwrap() < SystemTime::now());
        assert!(request.accepted_declined_timestamp.unwrap() > request.created_timestamp);

        let request = dao
            .get_buddy_request(created_buddy_requests[0].id, created_user2.id)
            .unwrap();

        assert_eq!(request.recipient_user_id, created_user2.id);
        assert_eq!(request.sender_user_id, created_user1.id);
        assert!(request.accepted);

        assert!(request.created_timestamp < SystemTime::now());
        assert!(request.accepted_declined_timestamp.unwrap() < SystemTime::now());
        assert!(request.accepted_declined_timestamp.unwrap() > request.created_timestamp);
    }

    #[test]
    fn test_create_buddy_relationship() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_user3 = generate_user().unwrap();
        let created_user4 = generate_user().unwrap();

        let buddy_relationships12 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        let buddy_relationships34 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user4.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationships12.len(), 0);
        assert_eq!(buddy_relationships34.len(), 0);

        let buddy_relationship12 = dao
            .create_buddy_relationship(created_user1.id, created_user2.id)
            .unwrap();
        let buddy_relationship34 = dao
            .create_buddy_relationship(created_user4.id, created_user3.id)
            .unwrap();

        assert!(buddy_relationship12.created_timestamp < SystemTime::now());
        assert!(buddy_relationship34.created_timestamp < SystemTime::now());
    }

    #[test]
    fn test_delete_buddy_relationship() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        let created_user3 = generate_user().unwrap();
        let created_user4 = generate_user().unwrap();

        let buddy_relationships12 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        let buddy_relationships34 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationships12.len(), 0);
        assert_eq!(buddy_relationships34.len(), 0);

        dao.create_buddy_relationship(created_user1.id, created_user2.id)
            .unwrap();
        dao.create_buddy_relationship(created_user4.id, created_user3.id)
            .unwrap();

        let buddy_relationships12 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        let buddy_relationships34 = buddy_relationships
            .filter(buddy_relationship_fields::user2_id.eq(created_user3.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationships12.len(), 1);
        assert_eq!(buddy_relationships34.len(), 1);

        let affected_row_count = dao
            .delete_buddy_relationship(created_user2.id, created_user1.id)
            .unwrap();
        assert_eq!(affected_row_count, 1);

        let buddy_relationships12 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        let buddy_relationships34 = buddy_relationships
            .filter(buddy_relationship_fields::user2_id.eq(created_user3.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationships12.len(), 0);
        assert_eq!(buddy_relationships34.len(), 1);

        let affected_row_count = dao
            .delete_buddy_relationship(created_user4.id, created_user3.id)
            .unwrap();
        assert_eq!(affected_row_count, 1);

        let buddy_relationships12 = buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(created_user1.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        let buddy_relationships34 = buddy_relationships
            .filter(buddy_relationship_fields::user2_id.eq(created_user3.id))
            .load::<BuddyRelationship>(&mut db_connection)
            .unwrap();

        assert_eq!(buddy_relationships12.len(), 0);
        assert_eq!(buddy_relationships34.len(), 0);
    }

    #[test]
    fn test_get_buddies() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();
        let created_user3 = generate_user().unwrap();
        let created_user4 = generate_user().unwrap();

        dao.create_buddy_relationship(created_user1.id, created_user2.id)
            .unwrap();
        dao.create_buddy_relationship(created_user1.id, created_user3.id)
            .unwrap();
        dao.create_buddy_relationship(created_user1.id, created_user4.id)
            .unwrap();
        dao.create_buddy_relationship(created_user3.id, created_user4.id)
            .unwrap();

        let user1_buddies = dao.get_buddies(created_user1.id).unwrap();
        let user2_buddies = dao.get_buddies(created_user2.id).unwrap();
        let user3_buddies = dao.get_buddies(created_user3.id).unwrap();
        let user4_buddies = dao.get_buddies(created_user4.id).unwrap();

        assert_eq!(user1_buddies.len(), 3);
        assert_eq!(user2_buddies.len(), 1);
        assert_eq!(user3_buddies.len(), 2);
        assert_eq!(user4_buddies.len(), 2);

        assert_eq!(user1_buddies[0].id, created_user2.id);
        assert_eq!(user1_buddies[1].id, created_user3.id);
        assert_eq!(user1_buddies[2].id, created_user4.id);

        assert_eq!(user2_buddies[0].id, created_user1.id);

        assert_eq!(user3_buddies[0].id, created_user1.id);
        assert_eq!(user3_buddies[1].id, created_user4.id);

        assert_eq!(user4_buddies[0].id, created_user1.id);
        assert_eq!(user4_buddies[1].id, created_user3.id);

        dao.create_buddy_relationship(created_user1.id, created_user2.id)
            .unwrap_err();
    }

    #[test]
    fn test_check_are_buddies() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user1 = generate_user().unwrap();
        let created_user2 = generate_user().unwrap();

        assert!(!dao
            .check_are_buddies(created_user1.id, created_user2.id)
            .unwrap());
        assert!(!dao
            .check_are_buddies(created_user2.id, created_user1.id)
            .unwrap());

        dao.create_buddy_relationship(created_user1.id, created_user2.id)
            .unwrap();

        assert!(dao
            .check_are_buddies(created_user1.id, created_user2.id)
            .unwrap());
        assert!(dao
            .check_are_buddies(created_user2.id, created_user1.id)
            .unwrap());
    }
}
