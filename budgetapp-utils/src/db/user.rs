use actix_web::web;
use diesel::{dsl, sql_query, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::cell::RefCell;
use std::rc::Rc;
use uuid::Uuid;

use crate::db::{DaoError, DataAccessor, DbConnection, DbThreadPool};
use crate::models::buddy_relationship::NewBuddyRelationship;
use crate::models::buddy_request::{BuddyRequest, NewBuddyRequest};
use crate::models::user::{NewUser, User};
use crate::password_hasher;
use crate::request_io::{InputEditUser, InputUser};
use crate::schema::buddy_relationships as buddy_relationship_fields;
use crate::schema::buddy_relationships::dsl::buddy_relationships;
use crate::schema::buddy_requests as buddy_request_fields;
use crate::schema::buddy_requests::dsl::buddy_requests;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;

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

    pub fn get_user_by_id(&mut self, user_id: Uuid) -> Result<User, DaoError> {
        Ok(users
            .find(user_id)
            .first::<User>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_user_by_email(&mut self, user_email: &str) -> Result<User, DaoError> {
        Ok(users
            .filter(user_fields::email.eq(user_email.to_lowercase()))
            .first::<User>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn create_user(
        &mut self,
        user_data: &web::Json<InputUser>,
        hash_params: &password_hasher::HashParams,
        hashing_secret_key: &[u8],
    ) -> Result<User, DaoError> {
        let hashed_password =
            password_hasher::hash_password(&user_data.password, hash_params, hashing_secret_key);
        let current_time = chrono::Utc::now().naive_utc();

        let new_user = NewUser {
            id: Uuid::new_v4(),
            is_active: true,
            is_premium: false,
            premium_expiration: Option::None,
            email: &user_data.email.to_lowercase(),
            password_hash: &hashed_password,
            first_name: &user_data.first_name,
            last_name: &user_data.last_name,
            date_of_birth: user_data.date_of_birth,
            modified_timestamp: current_time,
            created_timestamp: current_time,
            currency: &user_data.currency,
        };

        Ok(dsl::insert_into(users)
            .values(&new_user)
            .get_result::<User>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn edit_user(
        &mut self,
        user_id: Uuid,
        edited_user_data: &web::Json<InputEditUser>,
    ) -> Result<usize, DaoError> {
        Ok(dsl::update(users.filter(user_fields::id.eq(user_id)))
            .set((
                user_fields::modified_timestamp.eq(chrono::Utc::now().naive_utc()),
                user_fields::first_name.eq(&edited_user_data.first_name),
                user_fields::last_name.eq(&edited_user_data.last_name),
                user_fields::date_of_birth.eq(&edited_user_data.date_of_birth),
                user_fields::currency.eq(&edited_user_data.currency),
            ))
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
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

        dsl::update(users.filter(user_fields::id.eq(user_id)))
            .set(user_fields::password_hash.eq(hashed_password))
            .execute(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(())
    }

    pub fn send_buddy_request(
        &mut self,
        recipient_user_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        let request = NewBuddyRequest {
            id: Uuid::new_v4(),
            recipient_user_id,
            sender_user_id,
            accepted: false,
            created_timestamp: chrono::Utc::now().naive_utc(),
            accepted_declined_timestamp: None,
        };

        Ok(dsl::insert_into(buddy_requests)
            .values(&request)
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
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
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
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
            buddy_request_fields::accepted_declined_timestamp.eq(chrono::Utc::now().naive_utc()),
        ))
        .get_result(&mut *(self.get_connection()?).borrow_mut())?)
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
            buddy_request_fields::accepted_declined_timestamp.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_all_pending_buddy_requests_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(user_id))
            .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
            .order(buddy_request_fields::created_timestamp.asc())
            .load::<BuddyRequest>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_all_pending_buddy_requests_made_by_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BuddyRequest>, DaoError> {
        Ok(buddy_requests
            .filter(buddy_request_fields::sender_user_id.eq(user_id))
            .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
            .order(buddy_request_fields::created_timestamp.asc())
            .load::<BuddyRequest>(&mut *(self.get_connection()?).borrow_mut())?)
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
            .first::<BuddyRequest>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn create_buddy_relationship(
        &mut self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<usize, DaoError> {
        let current_time = chrono::Utc::now().naive_utc();

        let relationship = NewBuddyRelationship {
            created_timestamp: current_time,
            user1_id,
            user2_id,
        };

        Ok(dsl::insert_into(buddy_relationships)
            .values(&relationship)
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
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
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_buddies(&mut self, user_id: Uuid) -> Result<Vec<User>, DaoError> {
        let query = "SELECT u.* FROM users AS u, buddy_relationships AS br \
                     WHERE (br.user1_id = $1 AND u.id = br.user2_id) \
                     OR (br.user2_id = $1 AND u.id = br.user1_id) \
                     ORDER BY br.created_timestamp";

        Ok(sql_query(query)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .load(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn check_are_buddies(&mut self, user1_id: Uuid, user2_id: Uuid) -> Result<bool, DaoError> {
        Ok(diesel::dsl::select(diesel::dsl::exists(
            buddy_relationships.filter(
                buddy_relationship_fields::user1_id
                    .eq(user1_id)
                    .and(buddy_relationship_fields::user2_id.eq(user2_id))
                    .or(buddy_relationship_fields::user1_id
                        .eq(user2_id)
                        .and(buddy_relationship_fields::user2_id.eq(user1_id))),
            ),
        ))
        .get_result(&mut *(self.get_connection()?).borrow_mut())?)
    }
}
