use actix_web::web;
use diesel::{dsl, sql_query, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl};
use uuid::Uuid;

use crate::definitions::*;
use crate::handlers::request_io::{InputEditUser, InputUser};
use crate::models::buddy_relationship::NewBuddyRelationship;
use crate::models::buddy_request::{BuddyRequest, NewBuddyRequest};
use crate::models::user::{NewUser, User};
use crate::schema::buddy_relationships as buddy_relationship_fields;
use crate::schema::buddy_relationships::dsl::buddy_relationships;
use crate::schema::buddy_requests as buddy_request_fields;
use crate::schema::buddy_requests::dsl::buddy_requests;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;
use crate::utils::password_hasher;

pub fn get_user_by_id(
    db_connection: &DbConnection,
    user_id: Uuid,
) -> Result<User, diesel::result::Error> {
    users.find(user_id).first::<User>(db_connection)
}

pub fn get_user_by_email(
    db_connection: &DbConnection,
    user_email: &str,
) -> Result<User, diesel::result::Error> {
    users
        .filter(user_fields::email.eq(user_email.to_lowercase()))
        .first::<User>(db_connection)
}

pub fn create_user(
    db_connection: &DbConnection,
    user_data: &web::Json<InputUser>,
) -> Result<User, diesel::result::Error> {
    let hashed_password = password_hasher::hash_password(&user_data.password);
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

    dsl::insert_into(users)
        .values(&new_user)
        .get_result::<User>(db_connection)
}

pub fn edit_user(
    db_connection: &DbConnection,
    user_id: Uuid,
    edited_user_data: &web::Json<InputEditUser>,
) -> Result<usize, diesel::result::Error> {
    dsl::update(users.filter(user_fields::id.eq(user_id)))
        .set((
            user_fields::modified_timestamp.eq(chrono::Utc::now().naive_utc()),
            user_fields::first_name.eq(&edited_user_data.first_name),
            user_fields::last_name.eq(&edited_user_data.last_name),
            user_fields::date_of_birth.eq(&edited_user_data.date_of_birth),
            user_fields::currency.eq(&edited_user_data.currency),
        ))
        .execute(db_connection)
}

pub fn change_password(
    db_connection: &DbConnection,
    user_id: Uuid,
    new_password: &str,
) -> Result<(), diesel::result::Error> {
    let hashed_password = password_hasher::hash_password(new_password);

    match dsl::update(users.filter(user_fields::id.eq(user_id)))
        .set(user_fields::password_hash.eq(hashed_password))
        .execute(db_connection)
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn send_buddy_request(
    db_connection: &DbConnection,
    recipient_user_id: Uuid,
    sender_user_id: Uuid,
) -> Result<usize, diesel::result::Error> {
    let request = NewBuddyRequest {
        id: Uuid::new_v4(),
        recipient_user_id,
        sender_user_id,
        accepted: false,
        created_timestamp: chrono::Utc::now().naive_utc(),
        accepted_declined_timestamp: None,
    };

    dsl::insert_into(buddy_requests)
        .values(&request)
        .execute(db_connection)
}

pub fn delete_buddy_request(
    db_connection: &DbConnection,
    request_id: Uuid,
    sender_user_id: Uuid,
) -> Result<usize, diesel::result::Error> {
    diesel::delete(
        buddy_requests
            .find(request_id)
            .filter(buddy_request_fields::sender_user_id.eq(sender_user_id)),
    )
    .execute(db_connection)
}

pub fn mark_buddy_request_accepted(
    db_connection: &DbConnection,
    request_id: Uuid,
    recipient_user_id: Uuid,
) -> Result<BuddyRequest, diesel::result::Error> {
    diesel::update(
        buddy_requests
            .find(request_id)
            .filter(buddy_request_fields::recipient_user_id.eq(recipient_user_id)),
    )
    .set((
        buddy_request_fields::accepted.eq(true),
        buddy_request_fields::accepted_declined_timestamp.eq(chrono::Utc::now().naive_utc()),
    ))
    .get_result(db_connection)
}

pub fn mark_buddy_request_declined(
    db_connection: &DbConnection,
    request_id: Uuid,
    recipient_user_id: Uuid,
) -> Result<usize, diesel::result::Error> {
    diesel::update(
        buddy_requests
            .find(request_id)
            .filter(buddy_request_fields::recipient_user_id.eq(recipient_user_id)),
    )
    .set((
        buddy_request_fields::accepted.eq(false),
        buddy_request_fields::accepted_declined_timestamp.eq(chrono::Utc::now().naive_utc()),
    ))
    .execute(db_connection)
}

// TODO: Test
pub fn get_all_pending_buddy_requests_for_user(
    db_connection: &DbConnection,
    user_id: Uuid,
) -> Result<Vec<BuddyRequest>, diesel::result::Error> {
    buddy_requests
        .filter(buddy_request_fields::recipient_user_id.eq(user_id))
        .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
        .order(buddy_request_fields::created_timestamp.asc())
        .load::<BuddyRequest>(db_connection)
}

// TODO: Test
pub fn get_all_pending_buddy_requests_made_by_user(
    db_connection: &DbConnection,
    user_id: Uuid,
) -> Result<Vec<BuddyRequest>, diesel::result::Error> {
    buddy_requests
        .filter(buddy_request_fields::sender_user_id.eq(user_id))
        .filter(buddy_request_fields::accepted_declined_timestamp.is_null())
        .order(buddy_request_fields::created_timestamp.asc())
        .load::<BuddyRequest>(db_connection)
}

// TODO: Test
pub fn get_buddy_request(
    db_connection: &DbConnection,
    request_id: Uuid,
    user_id: Uuid,
) -> Result<BuddyRequest, diesel::result::Error> {
    buddy_requests
        .find(request_id)
        .filter(
            buddy_request_fields::sender_user_id
                .eq(user_id)
                .or(buddy_request_fields::recipient_user_id.eq(user_id)),
        )
        .first::<BuddyRequest>(db_connection)
}

// TODO: Test
pub fn create_buddy_relationship(
    db_connection: &DbConnection,
    user1_id: Uuid,
    user2_id: Uuid,
) -> Result<usize, diesel::result::Error> {
    let current_time = chrono::Utc::now().naive_utc();

    let relationship = NewBuddyRelationship {
        created_timestamp: current_time,
        user1_id,
        user2_id,
    };

    dsl::insert_into(buddy_relationships)
        .values(&relationship)
        .execute(db_connection)
}

// TODO: Test
pub fn delete_buddy_relationship(
    db_connection: &DbConnection,
    user1_id: Uuid,
    user2_id: Uuid,
) -> Result<usize, diesel::result::Error> {
    diesel::delete(
        buddy_relationships
            .filter(buddy_relationship_fields::user1_id.eq(user1_id))
            .filter(buddy_relationship_fields::user2_id.eq(user2_id)),
    )
    .execute(db_connection)
}

// TODO: Test
pub fn get_buddies(
    db_connection: &DbConnection,
    user_id: Uuid,
) -> Result<Vec<User>, diesel::result::Error> {
    let query = "SELECT u.* FROM users AS u, buddy_relationships AS br \
                 WHERE (br.user1_id = $1 AND u.id = br.user2_id) \
                 OR (br.user2_id = $1 AND u.id = br.user1_id) \
                 ORDER BY br.created_timestamp";

    sql_query(query)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .load(db_connection)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use chrono::NaiveDate;
    use rand::prelude::*;

    use crate::env;
    use crate::models::buddy_relationship::BuddyRelationship;
    use crate::models::buddy_request::BuddyRequest;
    use crate::schema::buddy_requests as buddy_request_fields;
    use crate::schema::buddy_requests::dsl::buddy_requests;

    pub fn generate_user(db_connection: &DbConnection) -> Result<User, diesel::result::Error> {
        let user_number = rand::thread_rng().gen_range::<u32, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", user_number),
            password: String::from("g&eWi3#oIKDW%cTu*5*2"),
            first_name: format!("Test-{}", user_number),
            last_name: format!("User-{}", user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user);
        create_user(db_connection, &new_user_json)
    }

    #[actix_rt::test]
    async fn test_create_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "X$KC3%s&L91m!bVA*@Iu";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user.clone());
        create_user(&db_connection, &new_user_json).unwrap();

        let created_user = users
            .filter(user_fields::email.eq(&new_user.email.to_lowercase()))
            .first::<User>(&db_connection)
            .unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[actix_rt::test]
    async fn test_get_user_by_email() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "Uo^Z56o%f#@8Ub#I9D&f";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let user_email = format!("test_user{}@test.com", &user_number);
        let new_user = InputUser {
            email: user_email.clone(),
            password: PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user.clone());
        create_user(&db_connection, &new_user_json).unwrap();

        let created_user = get_user_by_email(&db_connection, &user_email).unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[actix_rt::test]
    async fn test_get_user_by_id() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "Uo^Z56o%f#@8Ub#I9D&f";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user.clone());
        let user_id = create_user(&db_connection, &new_user_json).unwrap().id;

        let created_user = get_user_by_id(&db_connection, user_id).unwrap();

        assert_eq!(&new_user.email, &created_user.email);
        assert_ne!(&new_user.password, &created_user.password_hash);
        assert_eq!(&new_user.first_name, &created_user.first_name);
        assert_eq!(&new_user.last_name, &created_user.last_name);
        assert_eq!(&new_user.date_of_birth, &created_user.date_of_birth);
        assert_eq!(&new_user.currency, &created_user.currency);
    }

    #[actix_rt::test]
    async fn test_edit_user_one_field() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "C4R1pUr2E2fG5qKPT&&s";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user);
        let user_before = create_user(&db_connection, &new_user_json).unwrap();

        let user_edits = InputEditUser {
            first_name: String::from("Edited Name"),
            last_name: user_before.last_name.clone(),
            date_of_birth: user_before.date_of_birth.clone(),
            currency: user_before.currency.clone(),
        };

        let user_edits_json = web::Json(user_edits.clone());
        edit_user(&db_connection, user_before.id, &user_edits_json).unwrap();

        let user_after = get_user_by_id(&db_connection, user_before.id).unwrap();

        assert_eq!(&user_after.email, &user_before.email);
        assert_eq!(&user_after.last_name, &user_before.last_name);
        assert_eq!(&user_after.date_of_birth, &user_before.date_of_birth);
        assert_eq!(&user_after.currency, &user_before.currency);

        assert_eq!(&user_after.password_hash, &user_before.password_hash);

        assert_eq!(&user_after.first_name, &user_edits.first_name);
    }

    #[actix_rt::test]
    async fn test_edit_user_all_fields() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const PASSWORD: &str = "C4R1pUr2E2fG5qKPT&&s";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user.clone());
        let user_before = create_user(&db_connection, &new_user_json).unwrap();

        let user_edits = InputEditUser {
            first_name: String::from("Edited"),
            last_name: String::from("Name"),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1940..=1949),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("DOP"),
        };

        let user_edits_json = web::Json(user_edits.clone());
        edit_user(&db_connection, user_before.id, &user_edits_json).unwrap();

        let user_after = get_user_by_id(&db_connection, user_before.id).unwrap();

        assert_eq!(&user_after.password_hash, &user_before.password_hash);

        assert_eq!(&user_after.email, &new_user.email);
        assert_eq!(&user_after.first_name, &user_edits.first_name);
        assert_eq!(&user_after.last_name, &user_edits.last_name);
        assert_eq!(&user_after.date_of_birth, &user_edits.date_of_birth);
        assert_eq!(&user_after.currency, &user_edits.currency);
    }

    #[actix_rt::test]
    async fn test_change_password() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        const ORIGINAL_PASSWORD: &str = "Eq&6T@Vyz54O%DoX$";
        const UPDATED_PASSWORD: &str = "P*%OaTMaMl^Uzft^$82Qn";

        let user_number = rand::thread_rng().gen_range::<u128, _>(10_000_000..100_000_000);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: ORIGINAL_PASSWORD.to_string(),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: NaiveDate::from_ymd(
                rand::thread_rng().gen_range(1950..=2020),
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            currency: String::from("USD"),
        };

        let new_user_json = web::Json(new_user);
        let user_id = create_user(&db_connection, &new_user_json).unwrap().id;

        let original_password_saved_hash = users
            .find(user_id)
            .select(user_fields::password_hash)
            .get_result::<String>(&db_connection)
            .unwrap();

        assert!(password_hasher::verify_hash(
            ORIGINAL_PASSWORD,
            &original_password_saved_hash
        ));

        change_password(&db_connection, user_id, UPDATED_PASSWORD).unwrap();

        let updated_password_saved_hash = users
            .find(user_id)
            .select(user_fields::password_hash)
            .get_result::<String>(&db_connection)
            .unwrap();

        assert_ne!(original_password_saved_hash, updated_password_saved_hash);
        assert!(password_hasher::verify_hash(
            UPDATED_PASSWORD,
            &updated_password_saved_hash
        ));
    }
    
    #[actix_rt::test]
    async fn test_send_buddy_request() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user(&db_connection).unwrap();
        let created_user2 = generate_user(&db_connection).unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        send_buddy_request(
            &db_connection,
            created_user2.id,
            created_user1.id,
        )
        .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.id
        );

        assert_eq!(created_buddy_requests[0].accepted, false);

        assert!(created_buddy_requests[0].created_timestamp < chrono::Utc::now().naive_utc());
        assert_eq!(
            created_buddy_requests[0].accepted_declined_timestamp,
            None
        );
    }

    #[actix_rt::test]
    async fn test_delete_buddy_request() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user(&db_connection).unwrap();
        let created_user2 = generate_user(&db_connection).unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        send_buddy_request(
            &db_connection,
            created_user2.id,
            created_user1.id,
        )
        .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        delete_buddy_request(
            &db_connection,
            created_buddy_requests[0].id,
            created_user1.id,
        )
            .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);
    }
    
    #[actix_rt::test]
    async fn test_mark_buddy_request_accepted() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user(&db_connection).unwrap();
        let created_user2 = generate_user(&db_connection).unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        send_buddy_request(
            &db_connection,
            created_user2.id,
            created_user1.id,
        )
        .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let returned_buddy_request = mark_buddy_request_accepted(
            &db_connection,
            created_buddy_requests[0].id,
            created_user2.id,
        )
        .unwrap();

        assert_eq!(returned_buddy_request.recipient_user_id, created_user2.id);
        assert_eq!(returned_buddy_request.sender_user_id, created_user1.id);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.id
        );

        assert_eq!(created_buddy_requests[0].accepted, true);

        assert!(created_buddy_requests[0].created_timestamp < chrono::Utc::now().naive_utc());
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                < chrono::Utc::now().naive_utc()
        );
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_buddy_requests[0].created_timestamp
        );
    }

    #[actix_rt::test]
    async fn test_mark_buddy_request_declined() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let created_user1 = generate_user(&db_connection).unwrap();
        let created_user2 = generate_user(&db_connection).unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 0);

        send_buddy_request(
            &db_connection,
            created_user2.id,
            created_user1.id,
        )
        .unwrap();

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();

        assert_eq!(created_buddy_requests.len(), 1);

        let returned_buddy_request_count = mark_buddy_request_declined(
            &db_connection,
            created_buddy_requests[0].id,
            created_user2.id,
        )
        .unwrap();

        assert_eq!(returned_buddy_request_count, 1);

        let created_buddy_requests = buddy_requests
            .filter(buddy_request_fields::recipient_user_id.eq(created_user2.id))
            .filter(buddy_request_fields::sender_user_id.eq(created_user1.id))
            .load::<BuddyRequest>(&db_connection)
            .unwrap();
        
        assert_eq!(created_buddy_requests.len(), 1);

        assert_eq!(
            created_buddy_requests[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_buddy_requests[0].sender_user_id,
            created_user1.id
        );

        assert_eq!(created_buddy_requests[0].accepted, false);

        assert!(created_buddy_requests[0].created_timestamp < chrono::Utc::now().naive_utc());
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                < chrono::Utc::now().naive_utc()
        );
        assert!(
            created_buddy_requests[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_buddy_requests[0].created_timestamp
        );
    }
}
