use diesel::{dsl, BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl, RunQueryDsl};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::buddy_relationship::NewBuddyRelationship;
use crate::models::buddy_request::{BuddyRequest, NewBuddyRequest};
use crate::models::user::NewUser;
use crate::models::user_deletion_request::{NewUserDeletionRequest, UserDeletionRequest};
use crate::models::user_preferences::NewUserPreferences;
use crate::models::user_security_data::NewUserSecurityData;
use crate::models::user_tombstone::{NewUserTombstone, UserTombstone};

use crate::request_io::InputUser;
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
use crate::schema::user_preferences as user_preferences_fields;
use crate::schema::user_preferences::dsl::user_preferences;
use crate::schema::user_security_data as user_security_data_fields;
use crate::schema::user_security_data::dsl::user_security_data;
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

    pub fn get_user_email(&mut self, user_id: Uuid) -> Result<String, DaoError> {
        Ok(users
            .select(user_fields::email)
            .find(user_id)
            .get_result::<String>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn lookup_user_id_by_email(&mut self, user_email: &str) -> Result<Uuid, DaoError> {
        Ok(users
            .select(user_fields::id)
            .filter(user_fields::email.eq(user_email.to_lowercase()))
            .get_result::<Uuid>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn create_user(
        &mut self,
        user_data: &InputUser,
        auth_string_hash: &str,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let user_id = Uuid::new_v4();

        let new_user = NewUser {
            id: user_id,
            email: &user_data.email.to_lowercase(),
            is_verified: false,
            created_timestamp: current_time,
        };

        let new_user_security_data = NewUserSecurityData {
            user_id,

            auth_string_hash: &auth_string_hash,
            auth_string_salt: &user_data.auth_string_salt,
            auth_string_iters: user_data.auth_string_iters,

            password_encryption_salt: &user_data.password_encryption_salt,
            password_encryption_iters: user_data.password_encryption_iters,

            recovery_key_salt: &user_data.recovery_key_salt,
            recovery_key_iters: user_data.recovery_key_iters,

            encryption_key_user_password_encrypted: &user_data
                .encryption_key_user_password_encrypted,
            encryption_key_recovery_key_encrypted: &user_data.encryption_key_recovery_key_encrypted,

            public_rsa_key: &user_data.public_rsa_key,
            private_rsa_key_encrypted: &user_data.private_rsa_key_encrypted,
            rsa_key_created_timestamp: SystemTime::now(),

            last_token_refresh_timestamp: current_time,
            modified_timestamp: current_time,
        };

        let new_user_preferences = NewUserPreferences {
            user_id,
            encrypted_blob: &user_data.preferences_encrypted,
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(users).values(&new_user).execute(conn)?;

                dsl::insert_into(user_security_data)
                    .values(&new_user_security_data)
                    .execute(conn)?;

                dsl::insert_into(user_preferences)
                    .values(&new_user_preferences)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(user_id)
    }

    pub fn verify_user_creation(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        dsl::update(users.find(user_id))
            .set(user_fields::is_verified.eq(true))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn update_user_prefs(
        &mut self,
        user_id: Uuid,
        prefs_encrypted_blob: &str,
    ) -> Result<(), DaoError> {
        dsl::update(user_preferences.find(user_id))
            .set((
                user_preferences_fields::encrypted_blob.eq(prefs_encrypted_blob),
                user_preferences_fields::modified_timestamp.eq(SystemTime::now()),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn set_last_token_refresh_now(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        dsl::update(user_security_data.filter(user_security_data_fields::user_id.eq(user_id)))
            .set(user_security_data_fields::last_token_refresh_timestamp.eq(SystemTime::now()))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn update_password(
        &mut self,
        user_id: Uuid,
        new_auth_string_hash: &str,
        new_auth_string_salt: &str,
        new_auth_string_iters: i32,
        encrypted_encryption_key: &str,
    ) -> Result<(), DaoError> {
        dsl::update(user_security_data.filter(user_security_data_fields::user_id.eq(user_id)))
            .set((
                user_security_data_fields::auth_string_hash.eq(new_auth_string_hash),
                user_security_data_fields::auth_string_salt.eq(new_auth_string_salt),
                user_security_data_fields::auth_string_iters.eq(new_auth_string_iters),
                user_security_data_fields::encryption_key_user_password_encrypted
                    .eq(encrypted_encryption_key),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn send_buddy_request(
        &mut self,
        recipient_user_id: Uuid,
        sender_user_id: Uuid,
        sender_name_encrypted: Option<&str>,
    ) -> Result<BuddyRequest, DaoError> {
        let request = NewBuddyRequest {
            id: Uuid::new_v4(),
            recipient_user_id,
            sender_user_id,
            sender_name_encrypted,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        let buddy_request = db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                let are_buddies = dsl::select(dsl::exists(
                    buddy_relationships.filter(
                        buddy_relationship_fields::user1_id
                            .eq(sender_user_id)
                            .and(buddy_relationship_fields::user2_id.eq(recipient_user_id))
                            .or(buddy_relationship_fields::user1_id
                                .eq(recipient_user_id)
                                .and(buddy_relationship_fields::user2_id.eq(sender_user_id))),
                    ),
                ))
                .get_result::<bool>(conn)?;

                if are_buddies {
                    return Err(DaoError::WontRunQuery);
                }

                Ok(dsl::insert_into(buddy_requests)
                    .values(&request)
                    .on_conflict((
                        buddy_request_fields::recipient_user_id,
                        buddy_request_fields::sender_user_id,
                    ))
                    .do_update()
                    .set(buddy_request_fields::sender_name_encrypted.eq(sender_name_encrypted))
                    .get_result::<BuddyRequest>(conn)?)
            })?;

        Ok(buddy_request)
    }

    pub fn delete_buddy_request(
        &mut self,
        request_id: Uuid,
        sender_or_recipient_user_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::delete(
            buddy_requests.find(request_id).filter(
                buddy_request_fields::sender_user_id
                    .eq(sender_or_recipient_user_id)
                    .or(buddy_request_fields::recipient_user_id.eq(sender_or_recipient_user_id)),
            ),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn accept_buddy_request(
        &mut self,
        request_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let sender_user_id = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let sender_user_id = diesel::delete(
                    buddy_requests
                        .find(request_id)
                        .filter(buddy_request_fields::recipient_user_id.eq(recipient_user_id)),
                )
                .returning(buddy_request_fields::sender_user_id)
                .get_result::<Uuid>(conn)?;

                let relationship = NewBuddyRelationship {
                    user1_id: sender_user_id,
                    user2_id: recipient_user_id,
                };

                dsl::insert_into(buddy_relationships)
                    .values(&relationship)
                    .execute(conn)?;

                Ok(sender_user_id)
            })?;

        Ok(sender_user_id)
    }

    pub fn get_all_pending_buddy_requests_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(user_id))
            .load::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_all_pending_buddy_requests_made_by_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(user_id))
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
            .get_result::<BuddyRequest>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn delete_buddy_relationship(
        &mut self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::delete(
            buddy_relationships.filter(
                buddy_relationship_fields::user1_id
                    .eq(user1_id)
                    .and(buddy_relationship_fields::user2_id.eq(user2_id))
                    .or(buddy_relationship_fields::user1_id
                        .eq(user2_id)
                        .and(buddy_relationship_fields::user2_id.eq(user1_id))),
            ),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn get_buddies(&mut self, user_id: Uuid) -> Result<Vec<Uuid>, DaoError> {
        Ok(users
            .select(user_fields::id)
            .left_join(
                buddy_relationships.on(buddy_relationship_fields::user1_id
                    .eq(user_fields::id)
                    .or(buddy_relationship_fields::user2_id.eq(user_fields::id))),
            )
            .filter(
                buddy_relationship_fields::user1_id
                    .eq(user_id)
                    .or(buddy_relationship_fields::user2_id.eq(user_id)),
            )
            .get_results::<Uuid>(&mut self.db_thread_pool.get()?)?)
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

    pub fn initiate_user_deletion(
        &mut self,
        user_id: Uuid,
        time_until_deletion: Duration,
    ) -> Result<(), DaoError> {
        let new_request = NewUserDeletionRequest {
            user_id,
            deletion_request_time: SystemTime::now(),
            ready_for_deletion_time: SystemTime::now() + time_until_deletion,
        };

        dsl::insert_into(user_deletion_requests)
            .values(&new_request)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn cancel_user_deletion(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            user_deletion_requests.filter(user_deletion_request_fields::user_id.eq(user_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn delete_user(&mut self, request: &UserDeletionRequest) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let new_tombstone = NewUserTombstone {
            user_id: request.user_id,
            deletion_timestamp: SystemTime::now(),
        };

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(user_tombstones)
                    .values(&new_tombstone)
                    .execute(conn)?;

                diesel::delete(budgets)
                    .filter(
                        user_budgets
                            .filter(user_budget_fields::user_id.eq(request.user_id))
                            .filter(budget_fields::id.eq(user_budget_fields::budget_id))
                            .count()
                            .single_value()
                            .eq(1),
                    )
                    .execute(conn)?;

                diesel::delete(users.find(request.user_id)).execute(conn)?;

                diesel::delete(
                    user_deletion_requests
                        .filter(user_deletion_request_fields::user_id.eq(request.user_id)),
                )
                .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn get_all_users_ready_for_deletion(
        &mut self,
    ) -> Result<Vec<UserDeletionRequest>, DaoError> {
        Ok(user_deletion_requests
            .filter(user_deletion_request_fields::ready_for_deletion_time.lt(SystemTime::now()))
            .get_results(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_user_tombstone(&mut self, user_id: Uuid) -> Result<UserTombstone, DaoError> {
        Ok(user_tombstones
            .filter(user_tombstone_fields::user_id.eq(user_id))
            .get_result::<UserTombstone>(&mut self.db_thread_pool.get()?)?)
    }
}
