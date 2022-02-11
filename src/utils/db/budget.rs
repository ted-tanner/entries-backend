use actix_web::web;
use diesel::{dsl, sql_query, BelongingToDsl, QueryDsl, RunQueryDsl};
use diesel::associations::GroupedBy;
use uuid::Uuid;

use crate::definitions::*;
use crate::handlers::request_io::{InputBudget, OutputBudget};
use crate::models::budget::{Budget, NewBudget};
use crate::models::category::{Category, NewCategory};
use crate::models::m2m::user_budget::NewUserBudget;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories::dsl::categories;
use crate::schema::user_budgets::dsl::user_budgets;

pub fn get_budget_by_id(
    db_connection: &DbConnection,
    budget_id: &Uuid,
) -> Result<OutputBudget, diesel::result::Error> {
    let budget = budgets.find(budget_id).first::<Budget>(db_connection)?;

    let loaded_categories = Category::belonging_to(&budget).load::<Category>(db_connection)?;

    let output_budget = OutputBudget {
        id: budget.id,
        is_shared: budget.is_shared,
        is_private: budget.is_private,
        is_deleted: budget.is_deleted,
        name: budget.name,
        description: budget.description,
        categories: loaded_categories,
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

    let loaded_categories = Category::belonging_to(&loaded_budgets)
        .load::<Category>(db_connection)?
        .grouped_by(&loaded_budgets);
    let categories_and_budgets = loaded_budgets
        .into_iter()
        .zip(loaded_categories)
        .collect::<Vec<_>>();

    let mut output_budgets = Vec::new();

    for budget_data in categories_and_budgets {
        let output_budget = OutputBudget {
            id: budget_data.0.id,
            is_shared: budget_data.0.is_shared,
            is_private: budget_data.0.is_private,
            is_deleted: budget_data.0.is_deleted,
            name: budget_data.0.name,
            description: budget_data.0.description,
            categories: budget_data.1,
            start_date: budget_data.0.start_date,
            end_date: budget_data.0.end_date,
            latest_entry_time: budget_data.0.latest_entry_time,
            modified_timestamp: budget_data.0.modified_timestamp,
            created_timestamp: budget_data.0.created_timestamp,
        };

        output_budgets.push(output_budget);
    }

    Ok(output_budgets)
}

// TODO: Get all budgets for user between dates

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
        start_date: budget.start_date,
        end_date: budget.end_date,
        latest_entry_time: budget.latest_entry_time,
        modified_timestamp: budget.modified_timestamp,
        created_timestamp: budget.created_timestamp,
    };

    Ok(output_budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::web;
    use chrono::NaiveDate;
    use rand::prelude::*;

    use crate::env;
    use crate::handlers::request_io::{InputBudget, InputUser};
    use crate::models::budget::{Budget, Categories, Category};
    use crate::models::m2m::user_budget::UserBudget;
    use crate::schema::budgets as budget_fields;
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::user_budgets as user_budget_fields;
    use crate::schema::user_budgets::dsl::user_budgets;

    #[test]
    fn test_create_budget() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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

        let new_user_json = web::Json(new_user.clone());
        let created_user = create_user(&db_connection, &new_user_json).unwrap();

        let category0 = Category {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = Category {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = Categories {
            category_list: vec![category0, category1],
        };

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: Some(budget_categories),
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

        let new_budget_json = web::Json(InputBudget);
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
        assert_eq!(budget.categories, new_budget.categories);
        assert_eq!(budget.start_date, new_budget.start_date);
        assert_eq!(budget.end_date, new_budget.end_date);
    }

    #[test]
    fn test_get_budget_by_id() {
        let db_thread_pool = &*env::testing::DB_THREAD_POOL;
        let db_connection = db_thread_pool.get().unwrap();

        let user_number = rand::thread_rng().gen_range(10_000_000..100_000_000);
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

        let new_user_json = web::Json(new_user.clone());
        let created_user = create_user(&db_connection, &new_user_json).unwrap();

        let category0 = Category {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = Category {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = Categories {
            category_list: vec![category0, category1],
        };

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: Some(budget_categories),
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

        let budget_id = create_budget(&db_connection, &web::Json(new_budget), &user_id)
            .unwrap()
            .id;
        let budget = get_budget_by_id(&budget_id).unwrap();

        assert_eq!(budget.name, new_budget.name);
        assert_eq!(budget.description, new_budget.description);
        assert_eq!(budget.categories, new_budget.categories);
        assert_eq!(budget.start_date, new_budget.start_date);
        assert_eq!(budget.end_date, new_budget.end_date);
    }

    // TODO
}
