use actix_web::web;
use chrono::NaiveDate;
use diesel::associations::GroupedBy;
use diesel::{dsl, sql_query, BelongingToDsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use uuid::Uuid;

use crate::definitions::*;
use crate::handlers::request_io::{InputBudget, InputEntry, OutputBudget};
use crate::models::budget::{Budget, NewBudget};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::models::m2m::user_budget::NewUserBudget;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories::dsl::categories;
use crate::schema::entries::dsl::entries;
use crate::schema::user_budgets::dsl::user_budgets;

pub fn get_budget_by_id(
    db_connection: &DbConnection,
    budget_id: &Uuid,
) -> Result<OutputBudget, diesel::result::Error> {
    let budget = budgets.find(budget_id).first::<Budget>(db_connection)?;

    let loaded_categories = Category::belonging_to(&budget).load::<Category>(db_connection)?;
    let loaded_entries = Entry::belonging_to(&budget).load::<Entry>(db_connection)?;

    let output_budget = OutputBudget {
        id: budget.id,
        is_shared: budget.is_shared,
        is_private: budget.is_private,
        is_deleted: budget.is_deleted,
        name: budget.name,
        description: budget.description,
        categories: loaded_categories,
        entries: loaded_entries,
        start_date: budget.start_date,
        end_date: budget.end_date,
        latest_entry_time: budget.latest_entry_time,
        modified_timestamp: budget.modified_timestamp,
        created_timestamp: budget.created_timestamp,
    };

    Ok(output_budget)
}

pub fn get_all_budgets_for_user(
    db_connection: &DbConnection,
    user_id: &Uuid,
) -> Result<Vec<OutputBudget>, diesel::result::Error> {
    let query = format!(
        "SELECT budgets.* FROM user_budgets, budgets \
        WHERE user_budgets.user_id = '{user_id}' \
        AND user_budgets.budget_id = budgets.id"
    );

    let loaded_budgets = sql_query(&query).load::<Budget>(db_connection)?;
    let mut loaded_categories = Category::belonging_to(&loaded_budgets)
        .load::<Category>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();
    let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
        .load::<Entry>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();

    let mut output_budgets = Vec::new();

    for budget in loaded_budgets.into_iter() {
        let output_budget = OutputBudget {
            id: budget.id,
            is_shared: budget.is_shared,
            is_private: budget.is_private,
            is_deleted: budget.is_deleted,
            name: budget.name,
            description: budget.description,
            categories: loaded_categories
                .next()
                .expect("Failed to fetch all categories for budget"),
            entries: loaded_entries
                .next()
                .expect("Failed to fetch all entries for budget"),
            start_date: budget.start_date,
            end_date: budget.end_date,
            latest_entry_time: budget.latest_entry_time,
            modified_timestamp: budget.modified_timestamp,
            created_timestamp: budget.created_timestamp,
        };

        output_budgets.push(output_budget);
    }

    Ok(output_budgets)
}

pub fn get_all_budgets_for_user_between_dates(
    db_connection: &DbConnection,
    user_id: &Uuid,
    start_date: NaiveDate,
    end_date: NaiveDate,
) -> Result<Vec<OutputBudget>, diesel::result::Error> {
    let query = format!(
        "SELECT budgets.* FROM user_budgets, budgets \
        WHERE user_budgets.user_id = '{user_id}' \
        AND user_budgets.budget_id = budgets.id \
        AND budgets.end_date >= '{start_date}' \
        AND budgets.start_date <= '{end_date}'"
    );

    let loaded_budgets = sql_query(&query).load::<Budget>(db_connection)?;
    let mut loaded_categories = Category::belonging_to(&loaded_budgets)
        .load::<Category>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();
    let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
        .load::<Entry>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();

    let mut output_budgets = Vec::new();

    for budget in loaded_budgets.into_iter() {
        let output_budget = OutputBudget {
            id: budget.id,
            is_shared: budget.is_shared,
            is_private: budget.is_private,
            is_deleted: budget.is_deleted,
            name: budget.name,
            description: budget.description,
            categories: loaded_categories
                .next()
                .expect("Failed to fetch all categories for budget"),
            entries: loaded_entries
                .next()
                .expect("Failed to fetch all entries for budget"),
            start_date: budget.start_date,
            end_date: budget.end_date,
            latest_entry_time: budget.latest_entry_time,
            modified_timestamp: budget.modified_timestamp,
            created_timestamp: budget.created_timestamp,
        };

        output_budgets.push(output_budget);
    }

    Ok(output_budgets)
}

pub fn create_budget(
    db_connection: &DbConnection,
    budget_data: &web::Json<InputBudget>,
    user_id: &Uuid,
) -> Result<OutputBudget, diesel::result::Error> {
    let current_time = chrono::Utc::now().naive_utc();
    let budget_id = Uuid::new_v4();

    let description = budget_data.description.as_deref();

    let new_budget = NewBudget {
        id: budget_id,
        is_shared: false,
        is_private: true,
        is_deleted: false,
        name: &budget_data.name,
        description,
        start_date: budget_data.start_date,
        end_date: budget_data.end_date,
        latest_entry_time: current_time,
        modified_timestamp: current_time,
        created_timestamp: current_time,
    };

    let budget = dsl::insert_into(budgets)
        .values(&new_budget)
        .get_result::<Budget>(db_connection)?;

    let new_user_budget_association = NewUserBudget {
        created_timestamp: current_time,
        user_id: *user_id,
        budget_id,
    };

    dsl::insert_into(user_budgets)
        .values(&new_user_budget_association)
        .execute(db_connection)?;

    let mut budget_categories = Vec::new();

    for category in &budget_data.categories {
        let new_category = NewCategory {
            budget_id,
            id: category.id,
            name: &category.name,
            limit_cents: category.limit_cents,
            color: &category.color,
        };

        budget_categories.push(new_category);
    }

    let inserted_categories = dsl::insert_into(categories)
        .values(budget_categories)
        .get_results::<Category>(db_connection)?;

    let output_budget = OutputBudget {
        id: budget.id,
        is_shared: budget.is_shared,
        is_private: budget.is_private,
        is_deleted: budget.is_deleted,
        name: budget.name,
        description: budget.description,
        categories: inserted_categories,
        entries: Vec::new(),
        start_date: budget.start_date,
        end_date: budget.end_date,
        latest_entry_time: budget.latest_entry_time,
        modified_timestamp: budget.modified_timestamp,
        created_timestamp: budget.created_timestamp,
    };

    Ok(output_budget)
}

pub fn create_entry(
    db_connection: &DbConnection,
    entry_data: &web::Json<InputEntry>,
    budget_id: &Uuid,
    user_id: &Uuid,
) -> Result<Entry, diesel::result::Error> {
    let current_time = chrono::Utc::now().naive_utc();
    let entry_id = Uuid::new_v4();

    let name = entry_data.name.as_deref();
    let note = entry_data.note.as_deref();

    let new_entry = NewEntry {
        id: entry_id,
        budget_id: *budget_id,
        user_id: *user_id,
        is_deleted: false,
        amount_cents: entry_data.amount_cents,
        date: entry_data.date,
        name,
        category: entry_data.category,
        note,
        modified_timestamp: current_time,
        created_timestamp: current_time,
    };

    let entry = dsl::insert_into(entries)
        .values(&new_entry)
        .get_result::<Entry>(db_connection)?;
    diesel::update(budgets.find(budget_id))
        .set(budget_fields::latest_entry_time.eq(current_time))
        .execute(db_connection)?;

    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::web;
    use chrono::NaiveDate;
    use diesel::ExpressionMethods;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{InputBudget, InputCategory, InputUser};
    use crate::models::budget::Budget;
    use crate::models::category::Category;
    use crate::models::m2m::user_budget::UserBudget;
    use crate::schema::budgets as budget_fields;
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::categories as category_fields;
    use crate::schema::categories::dsl::categories;
    use crate::schema::user_budgets as user_budget_fields;
    use crate::schema::user_budgets::dsl::user_budgets;
    use crate::utils::db::user;

    #[test]
    fn test_create_budget() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

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
        let created_user = user::create_user(&db_connection, &new_user_json).unwrap();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let new_budget_json = web::Json(new_budget.clone());
        create_budget(&db_connection, &new_budget_json, &created_user.id).unwrap();

        let created_user_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user.id))
            .load::<UserBudget>(&db_connection)
            .unwrap();

        assert_eq!(created_user_budget_associations.len(), 1);
        assert!(
            created_user_budget_associations[0].created_timestamp < chrono::Utc::now().naive_utc()
        );
        assert_eq!(created_user_budget_associations[0].user_id, created_user.id);

        let budget_id = created_user_budget_associations[0].budget_id;
        let budget = budgets
            .filter(budget_fields::id.eq(budget_id))
            .first::<Budget>(&db_connection)
            .unwrap();

        assert_eq!(budget.name, new_budget.name);
        assert_eq!(budget.description, new_budget.description);
        assert_eq!(budget.start_date, new_budget.start_date);
        assert_eq!(budget.end_date, new_budget.end_date);

        let saved_categories = categories
            .filter(category_fields::budget_id.eq(budget_id))
            .load::<Category>(&db_connection)
            .unwrap();

        assert_eq!(saved_categories[0].id, budget_categories[0].id);
        assert_eq!(saved_categories[0].name, budget_categories[0].name);
        assert_eq!(
            saved_categories[0].limit_cents,
            budget_categories[0].limit_cents
        );
        assert_eq!(saved_categories[0].color, budget_categories[0].color);
    }

    #[test]
    fn test_get_budget_by_id() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

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
        let created_user = user::create_user(&db_connection, &new_user_json).unwrap();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories,
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let new_budget_json = web::Json(new_budget);
        let created_budget =
            create_budget(&db_connection, &new_budget_json, &created_user.id).unwrap();

        let fetched_budget = get_budget_by_id(&db_connection, &created_budget.id).unwrap();

        assert_eq!(fetched_budget.id, created_budget.id);
        assert_eq!(fetched_budget.is_shared, created_budget.is_shared);
        assert_eq!(fetched_budget.is_private, created_budget.is_private);
        assert_eq!(fetched_budget.is_deleted, created_budget.is_deleted);
        assert_eq!(fetched_budget.name, created_budget.name);
        assert_eq!(fetched_budget.description, created_budget.description);
        assert_eq!(fetched_budget.start_date, created_budget.start_date);
        assert_eq!(fetched_budget.end_date, created_budget.end_date);
        assert_eq!(
            fetched_budget.latest_entry_time,
            created_budget.latest_entry_time
        );
        assert_eq!(
            fetched_budget.modified_timestamp,
            created_budget.modified_timestamp
        );
        assert_eq!(
            fetched_budget.created_timestamp,
            created_budget.created_timestamp
        );

        assert!(!fetched_budget.categories.is_empty());
        assert_eq!(
            fetched_budget.categories.len(),
            created_budget.categories.len()
        );

        for i in 0..fetched_budget.categories.len() {
            let fetched_cat = &fetched_budget.categories[i];
            let created_cat = &created_budget.categories[i];

            assert_eq!(fetched_cat.pk, created_cat.pk);
            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }
    }

    #[test]
    fn test_get_all_budgets_for_user() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

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
        let created_user = user::create_user(&db_connection, &new_user_json).unwrap();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let category2 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number} (Second Budget)"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category3 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number} (Second Budget)"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget0_categories = vec![category0, category1];
        let budget1_categories = vec![category2, category3];

        let new_budget0 = InputBudget {
            name: format!("Test Budget0 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget0 {user_number}.",
            )),
            categories: budget0_categories,
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let new_budget1 = InputBudget {
            name: format!("Test Budget1 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget1 {user_number}.",
            )),
            categories: budget1_categories,
            start_date: NaiveDate::from_ymd(
                2021,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2023,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let mut created_budgets = Vec::new();

        let new_budget0_json = web::Json(new_budget0);
        created_budgets
            .push(create_budget(&db_connection, &new_budget0_json, &created_user.id).unwrap());

        let new_budget1_json = web::Json(new_budget1);
        created_budgets
            .push(create_budget(&db_connection, &new_budget1_json, &created_user.id).unwrap());

        let fetched_budgets = get_all_budgets_for_user(&db_connection, &created_user.id).unwrap();
        assert_eq!(fetched_budgets.len(), created_budgets.len());

        for i in 0..fetched_budgets.len() {
            assert_eq!(fetched_budgets[i].id, created_budgets[i].id);
            assert_eq!(fetched_budgets[i].is_shared, created_budgets[i].is_shared);
            assert_eq!(fetched_budgets[i].is_private, created_budgets[i].is_private);
            assert_eq!(fetched_budgets[i].is_deleted, created_budgets[i].is_deleted);
            assert_eq!(fetched_budgets[i].name, created_budgets[i].name);
            assert_eq!(
                fetched_budgets[i].description,
                created_budgets[i].description
            );
            assert_eq!(fetched_budgets[i].start_date, created_budgets[i].start_date);
            assert_eq!(fetched_budgets[i].end_date, created_budgets[i].end_date);
            assert_eq!(
                fetched_budgets[i].latest_entry_time,
                created_budgets[i].latest_entry_time
            );
            assert_eq!(
                fetched_budgets[i].modified_timestamp,
                created_budgets[i].modified_timestamp
            );
            assert_eq!(
                fetched_budgets[i].created_timestamp,
                created_budgets[i].created_timestamp
            );

            assert!(!fetched_budgets[i].categories.is_empty());
            assert_eq!(
                fetched_budgets[i].categories.len(),
                created_budgets[i].categories.len()
            );

            for j in 0..fetched_budgets[i].categories.len() {
                let fetched_cat = &fetched_budgets[i].categories[j];
                let created_cat = &created_budgets[i].categories[j];

                assert_eq!(fetched_cat.pk, created_cat.pk);
                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }
        }
    }

    #[test]
    fn test_get_all_budgets_for_user_between_dates() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

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
        let created_user = user::create_user(&db_connection, &new_user_json).unwrap();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let too_early_budget = InputBudget {
            name: format!("Test Too_Early {user_number}"),
            description: Some(format!(
                "This is a description of Test Too_Early {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 3, 14),
            end_date: NaiveDate::from_ymd(2022, 3, 30),
        };

        let in_range_budget0 = InputBudget {
            name: format!("Test Budget1 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget1 {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 3, 12),
            end_date: NaiveDate::from_ymd(2022, 4, 18),
        };

        let in_range_budget1 = InputBudget {
            name: format!("Test Budget2 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget2 {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 4, 8),
            end_date: NaiveDate::from_ymd(2022, 4, 10),
        };

        let in_range_budget2 = InputBudget {
            name: format!("Test Budget2 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget2 {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: NaiveDate::from_ymd(2022, 4, 3),
            end_date: NaiveDate::from_ymd(2022, 5, 6),
        };

        let too_late_budget = InputBudget {
            name: format!("Test Budget3 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget3 {user_number}.",
            )),
            categories: budget_categories,
            start_date: NaiveDate::from_ymd(2022, 4, 22),
            end_date: NaiveDate::from_ymd(2022, 4, 30),
        };

        let mut in_range_budgets = Vec::new();

        let too_early_budget_json = web::Json(too_early_budget);
        create_budget(&db_connection, &too_early_budget_json, &created_user.id).unwrap();

        let in_range_too_early_json = web::Json(in_range_budget0);
        in_range_budgets.push(
            create_budget(&db_connection, &in_range_too_early_json, &created_user.id).unwrap(),
        );

        let in_range_budget1_json = web::Json(in_range_budget1);
        in_range_budgets
            .push(create_budget(&db_connection, &in_range_budget1_json, &created_user.id).unwrap());

        let in_range_budget2_json = web::Json(in_range_budget2);
        in_range_budgets
            .push(create_budget(&db_connection, &in_range_budget2_json, &created_user.id).unwrap());

        let too_late_budget_json = web::Json(too_late_budget);
        create_budget(&db_connection, &too_late_budget_json, &created_user.id).unwrap();

        let fetched_budgets = get_all_budgets_for_user_between_dates(
            &db_connection,
            &created_user.id,
            NaiveDate::from_ymd(2022, 4, 6),
            NaiveDate::from_ymd(2022, 4, 12),
        )
        .unwrap();
        assert_eq!(fetched_budgets.len(), in_range_budgets.len());

        for i in 0..fetched_budgets.len() {
            assert_eq!(fetched_budgets[i].id, in_range_budgets[i].id);
            assert_eq!(fetched_budgets[i].is_shared, in_range_budgets[i].is_shared);
            assert_eq!(
                fetched_budgets[i].is_private,
                in_range_budgets[i].is_private
            );
            assert_eq!(
                fetched_budgets[i].is_deleted,
                in_range_budgets[i].is_deleted
            );
            assert_eq!(fetched_budgets[i].name, in_range_budgets[i].name);
            assert_eq!(
                fetched_budgets[i].description,
                in_range_budgets[i].description
            );
            assert_eq!(
                fetched_budgets[i].start_date,
                in_range_budgets[i].start_date
            );
            assert_eq!(fetched_budgets[i].end_date, in_range_budgets[i].end_date);
            assert_eq!(
                fetched_budgets[i].latest_entry_time,
                in_range_budgets[i].latest_entry_time
            );
            assert_eq!(
                fetched_budgets[i].modified_timestamp,
                in_range_budgets[i].modified_timestamp
            );
            assert_eq!(
                fetched_budgets[i].created_timestamp,
                in_range_budgets[i].created_timestamp
            );

            assert!(!fetched_budgets[i].categories.is_empty());
            assert_eq!(
                fetched_budgets[i].categories.len(),
                in_range_budgets[i].categories.len()
            );

            for j in 0..fetched_budgets[i].categories.len() {
                let fetched_cat = &fetched_budgets[i].categories[j];
                let in_range_cat = &in_range_budgets[i].categories[j];

                assert_eq!(fetched_cat.pk, in_range_cat.pk);
                assert_eq!(fetched_cat.budget_id, in_range_cat.budget_id);
                assert_eq!(fetched_cat.id, in_range_cat.id);
                assert_eq!(fetched_cat.name, in_range_cat.name);
                assert_eq!(fetched_cat.limit_cents, in_range_cat.limit_cents);
                assert_eq!(fetched_cat.color, in_range_cat.color);
            }
        }
    }
}
