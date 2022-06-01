use actix_web::web;
use chrono::NaiveDate;
use diesel::associations::GroupedBy;
use diesel::{dsl, sql_query, BelongingToDsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use uuid::Uuid;

use crate::definitions::*;
use crate::handlers::request_io::{InputBudget, InputEditBudget, InputEntry, OutputBudget};
use crate::models::budget::{Budget, NewBudget};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::models::m2m::user_budget::NewUserBudget;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::entries as entry_fields;
use crate::schema::entries::dsl::entries;
use crate::schema::user_budgets as user_budget_fields;
use crate::schema::user_budgets::dsl::user_budgets;

pub fn get_budget_by_id(
    db_connection: &DbConnection,
    budget_id: Uuid,
) -> Result<OutputBudget, diesel::result::Error> {
    let budget = budgets.find(budget_id).first::<Budget>(db_connection)?;

    let loaded_categories = Category::belonging_to(&budget)
        .order(category_fields::id.asc())
        .load::<Category>(db_connection)?;
    let loaded_entries = Entry::belonging_to(&budget)
        .order(entry_fields::date.asc())
        .load::<Entry>(db_connection)?;

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
    user_id: Uuid,
) -> Result<Vec<OutputBudget>, diesel::result::Error> {
    // The use of this raw(ish) query is safe because the input (user_id) comes from a signed JWT.
    //
    // BEWARE of using this function when the user_id comes as input directly from the client.
    let query = format!(
        "SELECT budgets.* FROM user_budgets, budgets \
        WHERE user_budgets.user_id = '{user_id}' \
        AND user_budgets.budget_id = budgets.id \
	ORDER BY budgets.start_date"
    );

    let loaded_budgets = sql_query(&query).load::<Budget>(db_connection)?;
    let mut loaded_categories = Category::belonging_to(&loaded_budgets)
        .order(category_fields::id.asc())
        .load::<Category>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();
    let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
        .order(entry_fields::date.asc())
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
    user_id: Uuid,
    start_date: NaiveDate,
    end_date: NaiveDate,
) -> Result<Vec<OutputBudget>, diesel::result::Error> {
    // The use of this raw(ish) query is safe because the user_id comes from a signed JWT and the
    // dates are type-checked when they are deserialized.
    //
    // BEWARE of using this function when either the user_id or the dates come as input directly
    // from the client.

    let query = format!(
        "SELECT budgets.* FROM user_budgets, budgets \
        WHERE user_budgets.user_id = '{user_id}' \
        AND user_budgets.budget_id = budgets.id \
        AND budgets.end_date >= '{start_date}' \
        AND budgets.start_date <= '{end_date}' \
        ORDER BY budgets.start_date"
    );

    let loaded_budgets = sql_query(&query).load::<Budget>(db_connection)?;
    let mut loaded_categories = Category::belonging_to(&loaded_budgets)
        .order(category_fields::id.asc())
        .load::<Category>(db_connection)?
        .grouped_by(&loaded_budgets)
        .into_iter();
    let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
        .order(entry_fields::date.asc())
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

pub fn check_user_in_budget(
    db_connection: &DbConnection,
    user_id: Uuid,
    budget_id: Uuid,
) -> Result<bool, diesel::result::Error> {
    let association_exists = match user_budgets
        .filter(user_budget_fields::user_id.eq(user_id))
        .filter(user_budget_fields::budget_id.eq(budget_id))
        .execute(db_connection)
    {
        Ok(count) => count > 0,
        Err(e) => {
            if e == diesel::result::Error::NotFound {
                false
            } else {
                return Err(e);
            }
        }
    };

    Ok(association_exists)
}

pub fn create_budget(
    db_connection: &DbConnection,
    budget_data: &web::Json<InputBudget>,
    user_id: Uuid,
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
        user_id: user_id,
        budget_id,
    };

    dsl::insert_into(user_budgets)
        .values(&new_user_budget_association)
        .execute(db_connection)?;

    let mut budget_categories = Vec::new();

    for category in &budget_data.categories {
        let new_category = NewCategory {
            budget_id,
            is_deleted: false,
            id: category.id,
            name: &category.name,
            limit_cents: category.limit_cents,
            color: &category.color,
            modified_timestamp: budget.modified_timestamp,
            created_timestamp: budget.created_timestamp,
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

pub fn edit_budget(
    db_connection: &DbConnection,
    edited_budget_data: &web::Json<InputEditBudget>,
) -> Result<(), diesel::result::Error> {
    match dsl::update(budgets.filter(budget_fields::id.eq(edited_budget_data.id)))
        .set((
            budget_fields::name.eq(&edited_budget_data.name),
            budget_fields::description.eq(&edited_budget_data.description),
            budget_fields::start_date.eq(&edited_budget_data.start_date),
            budget_fields::end_date.eq(&edited_budget_data.end_date),
        ))
        .execute(db_connection)
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn create_entry(
    db_connection: &DbConnection,
    entry_data: &web::Json<InputEntry>,
    user_id: Uuid,
) -> Result<Entry, diesel::result::Error> {
    let current_time = chrono::Utc::now().naive_utc();
    let entry_id = Uuid::new_v4();

    let name = entry_data.name.as_deref();
    let note = entry_data.note.as_deref();

    let new_entry = NewEntry {
        id: entry_id,
        budget_id: entry_data.budget_id,
        user_id: user_id,
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
    diesel::update(budgets.find(new_entry.budget_id))
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
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::categories as category_fields;
    use crate::schema::categories::dsl::categories;
    use crate::schema::entries as entry_fields;
    use crate::schema::user_budgets as user_budget_fields;
    use crate::schema::user_budgets::dsl::user_budgets;
    use crate::utils::db::user;

    #[actix_rt::test]
    async fn test_create_budget() {
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
        create_budget(&db_connection, &new_budget_json, created_user.id).unwrap();

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
            .find(budget_id)
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

    #[actix_rt::test]
    async fn test_edit_budget_one_field() {
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

        let new_budget_json = web::Json(new_budget.clone());
        let budget_before =
            create_budget(&db_connection, &new_budget_json, created_user.id).unwrap();

        let budget_edits = InputEditBudget {
            id: budget_before.id.clone(),
            name: budget_before.name.clone(),
            description: None,
            start_date: budget_before.start_date.clone(),
            end_date: budget_before.end_date.clone(),
        };

        let budget_edits_json = web::Json(budget_edits.clone());
        edit_budget(&db_connection, &budget_edits_json).unwrap();

        let budget_after = get_budget_by_id(&db_connection, budget_before.id).unwrap();

        assert_eq!(&budget_after.name, &budget_before.name);
        assert_eq!(&budget_after.start_date, &budget_before.start_date);
        assert_eq!(&budget_after.end_date, &budget_before.end_date);

        for i in 0..budget_after.categories.len() {
            assert_eq!(
                budget_after.categories[i].id,
                budget_before.categories[i].id
            );
            assert_eq!(
                budget_after.categories[i].name,
                budget_before.categories[i].name
            );
            assert_eq!(
                budget_after.categories[i].limit_cents,
                budget_before.categories[i].limit_cents
            );
            assert_eq!(
                budget_after.categories[i].color,
                budget_before.categories[i].color
            );
        }

        assert_eq!(&budget_after.description, &budget_edits.description);
    }

    #[actix_rt::test]
    async fn test_edit_budget_all_fields() {
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

        let new_budget_json = web::Json(new_budget.clone());
        let budget_before =
            create_budget(&db_connection, &new_budget_json, created_user.id).unwrap();

        let budget_edits = InputEditBudget {
            id: budget_before.id.clone(),
            name: String::from("this is an edited budget name"),
            description: Some(String::from("This is an edited description for the budget")),
            start_date: NaiveDate::from_ymd(
                2024,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2025,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
        };

        let budget_edits_json = web::Json(budget_edits.clone());
        edit_budget(&db_connection, &budget_edits_json).unwrap();

        let budget_after = get_budget_by_id(&db_connection, budget_before.id).unwrap();

        assert_eq!(&budget_after.name, &budget_edits.name);
        assert_eq!(&budget_after.description, &budget_edits.description);
        assert_eq!(&budget_after.start_date, &budget_edits.start_date);
        assert_eq!(&budget_after.end_date, &budget_edits.end_date);

        for i in 0..budget_after.categories.len() {
            assert_eq!(
                budget_after.categories[i].id,
                budget_before.categories[i].id
            );
            assert_eq!(
                budget_after.categories[i].name,
                budget_before.categories[i].name
            );
            assert_eq!(
                budget_after.categories[i].limit_cents,
                budget_before.categories[i].limit_cents
            );
            assert_eq!(
                budget_after.categories[i].color,
                budget_before.categories[i].color
            );
        }
    }

    #[actix_rt::test]
    async fn test_create_entry() {
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
            create_budget(&db_connection, &new_budget_json, created_user.id).unwrap();

        let new_entry = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let new_entry_json = web::Json(new_entry.clone());
        let created_entry = create_entry(&db_connection, &new_entry_json, created_user.id).unwrap();

        let entry = entries
            .filter(entry_fields::id.eq(created_entry.id))
            .first::<Entry>(&db_connection)
            .unwrap();

        assert_eq!(entry.amount_cents, new_entry.amount_cents);
        assert_eq!(entry.date, new_entry.date);
        assert_eq!(entry.name, new_entry.name);
        assert_eq!(entry.category, new_entry.category);
        assert_eq!(entry.note, new_entry.note);

        let fetched_budget = get_budget_by_id(&db_connection, created_budget.id).unwrap();

        assert!(fetched_budget.latest_entry_time > created_budget.latest_entry_time);
        assert_eq!(fetched_budget.entries.len(), 1);

        let fetched_budget_entry = &fetched_budget.entries[0];
        assert_eq!(fetched_budget_entry.amount_cents, new_entry.amount_cents);
        assert_eq!(fetched_budget_entry.date, new_entry.date);
        assert_eq!(fetched_budget_entry.name, new_entry.name);
        assert_eq!(fetched_budget_entry.category, new_entry.category);
        assert_eq!(fetched_budget_entry.note, new_entry.note);
    }

    #[actix_rt::test]
    async fn test_get_budget_by_id() {
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
            description: None,
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
            create_budget(&db_connection, &new_budget_json, created_user.id).unwrap();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        let entry0_json = web::Json(entry0);
        let entry1_json = web::Json(entry1);
        create_entry(&db_connection, &entry0_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry1_json, created_user.id).unwrap();

        let fetched_budget = get_budget_by_id(&db_connection, created_budget.id).unwrap();

        assert_eq!(fetched_budget.id, created_budget.id);
        assert_eq!(fetched_budget.is_shared, created_budget.is_shared);
        assert_eq!(fetched_budget.is_private, created_budget.is_private);
        assert_eq!(fetched_budget.is_deleted, created_budget.is_deleted);
        assert_eq!(fetched_budget.name, created_budget.name);
        assert_eq!(fetched_budget.description, created_budget.description);
        assert_eq!(fetched_budget.start_date, created_budget.start_date);
        assert_eq!(fetched_budget.end_date, created_budget.end_date);

        assert!(fetched_budget.latest_entry_time > created_budget.latest_entry_time);

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

        assert!(!fetched_budget.entries.is_empty());
        assert_eq!(fetched_budget.entries.len(), created_entries.len());
        for i in 0..fetched_budget.entries.len() {
            let fetched_entry = &fetched_budget.entries[i];
            let created_entry = &created_entries[i];

            assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
            assert_eq!(fetched_entry.date, created_entry.date);
            assert_eq!(fetched_entry.name, created_entry.name);
            assert_eq!(fetched_entry.category, created_entry.category);
            assert_eq!(fetched_entry.note, created_entry.note);
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user() {
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
                2020,
                rand::thread_rng().gen_range(1..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            end_date: NaiveDate::from_ymd(
                2024,
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
            .push(create_budget(&db_connection, &new_budget0_json, created_user.id).unwrap());

        let new_budget1_json = web::Json(new_budget1);
        created_budgets
            .push(create_budget(&db_connection, &new_budget1_json, created_user.id).unwrap());

        let entry0 = InputEntry {
            budget_id: created_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_budgets[1].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(1..=6),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: Some(format!("Test Entry 2 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is 2 little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_budgets[1].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(
                2022,
                rand::thread_rng().gen_range(7..=12),
                rand::thread_rng().gen_range(1..=28),
            ),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![
            vec![entry0.clone(), entry1.clone()],
            vec![entry2.clone(), entry3.clone()],
        ];

        let entry0_json = web::Json(entry0);
        let entry1_json = web::Json(entry1);
        create_entry(&db_connection, &entry0_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry1_json, created_user.id).unwrap();

        let entry2_json = web::Json(entry2);
        let entry3_json = web::Json(entry3);
        create_entry(&db_connection, &entry2_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry3_json, created_user.id).unwrap();

        let fetched_budgets = get_all_budgets_for_user(&db_connection, created_user.id).unwrap();
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

            assert!(fetched_budgets[i].latest_entry_time > created_budgets[i].latest_entry_time);

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

            for j in 0..fetched_budgets[i].entries.len() {
                let fetched_entry = &fetched_budgets[i].entries[j];
                let created_entry = &created_entries[i][j];

                assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
                assert_eq!(fetched_entry.date, created_entry.date);
                assert_eq!(fetched_entry.name, created_entry.name);
                assert_eq!(fetched_entry.category, created_entry.category);
                assert_eq!(fetched_entry.note, created_entry.note);
            }
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user_between_dates() {
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
            start_date: NaiveDate::from_ymd(2022, 4, 9),
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
        create_budget(&db_connection, &too_early_budget_json, created_user.id).unwrap();

        let in_range_budget0_json = web::Json(in_range_budget0);
        in_range_budgets
            .push(create_budget(&db_connection, &in_range_budget0_json, created_user.id).unwrap());

        let in_range_budget1_json = web::Json(in_range_budget1);
        in_range_budgets
            .push(create_budget(&db_connection, &in_range_budget1_json, created_user.id).unwrap());

        let in_range_budget2_json = web::Json(in_range_budget2);
        in_range_budgets
            .push(create_budget(&db_connection, &in_range_budget2_json, created_user.id).unwrap());

        let too_late_budget_json = web::Json(too_late_budget);
        create_budget(&db_connection, &too_late_budget_json, created_user.id).unwrap();

        let entry0 = InputEntry {
            budget_id: in_range_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(2022, 4, 8),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: in_range_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: NaiveDate::from_ymd(2022, 4, 9),
            name: None,
            category: None,
            note: None,
        };

        let mut entry2 = entry0.clone();
        entry2.budget_id = in_range_budgets[1].id;

        let mut entry3 = entry1.clone();
        entry3.budget_id = in_range_budgets[1].id;

        let mut entry4 = entry0.clone();
        entry4.budget_id = in_range_budgets[2].id;

        let mut entry5 = entry1.clone();
        entry5.budget_id = in_range_budgets[2].id;

        let created_entries = vec![
            entry0.clone(),
            entry1.clone(),
            entry2.clone(),
            entry3.clone(),
            entry4.clone(),
            entry5.clone(),
        ];

        let entry0_json = web::Json(entry0);
        let entry1_json = web::Json(entry1);
        let entry2_json = web::Json(entry2);
        let entry3_json = web::Json(entry3);
        let entry4_json = web::Json(entry4);
        let entry5_json = web::Json(entry5);

        create_entry(&db_connection, &entry0_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry1_json, created_user.id).unwrap();

        create_entry(&db_connection, &entry2_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry3_json, created_user.id).unwrap();

        create_entry(&db_connection, &entry4_json, created_user.id).unwrap();
        create_entry(&db_connection, &entry5_json, created_user.id).unwrap();

        let fetched_budgets = get_all_budgets_for_user_between_dates(
            &db_connection,
            created_user.id,
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

            assert!(fetched_budgets[i].latest_entry_time > in_range_budgets[i].latest_entry_time);

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

            for j in 0..fetched_budgets[i].entries.len() {
                let fetched_entry = &fetched_budgets[i].entries[j];
                let created_entry = &created_entries[j];

                assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
                assert_eq!(fetched_entry.date, created_entry.date);
                assert_eq!(fetched_entry.name, created_entry.name);
                assert_eq!(fetched_entry.category, created_entry.category);
                assert_eq!(fetched_entry.note, created_entry.note);
            }
        }
    }
}
