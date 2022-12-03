use actix_web::web;
use chrono::NaiveDate;
use diesel::associations::GroupedBy;
use diesel::sql_types::{self, Date, Nullable, Text, Timestamp, VarChar};
use diesel::{
    dsl, sql_query, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl,
    RunQueryDsl,
};
use std::cell::RefCell;
use std::rc::Rc;
use uuid::Uuid;

use crate::db::{DaoError, DataAccessor, DbConnection, DbThreadPool};
use crate::models::budget::{Budget, NewBudget};
use crate::models::budget_share_event::{BudgetShareEvent, NewBudgetShareEvent};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::models::user_budget::NewUserBudget;
use crate::request_io::{InputBudget, InputEditBudget, InputEntry, OutputBudget};
use crate::schema::budget_share_events as budget_share_event_fields;
use crate::schema::budget_share_events::dsl::budget_share_events;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::entries as entry_fields;
use crate::schema::entries::dsl::entries;
use crate::schema::user_budgets as user_budget_fields;
use crate::schema::user_budgets::dsl::user_budgets;

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

    pub fn get_budget_by_id(
        &mut self,
        budget_id: Uuid,
        user_id: Uuid,
    ) -> Result<OutputBudget, DaoError> {
        let mut loaded_budgets = budgets
            .select(budget_fields::all_columns)
            .left_join(user_budgets.on(user_budget_fields::budget_id.eq(budget_id)))
            .filter(budget_fields::id.eq(budget_id))
            .filter(user_budget_fields::user_id.eq(user_id))
            .load::<Budget>(&mut *(self.get_connection()?).borrow_mut())?;

        if loaded_budgets.len() != 1 {
            return Err(diesel::result::Error::NotFound.into());
        }

        let budget = loaded_budgets.remove(0);

        let loaded_categories = Category::belonging_to(&budget)
            .order(category_fields::id.asc())
            .load::<Category>(&mut *(self.get_connection()?).borrow_mut())?;
        let loaded_entries = Entry::belonging_to(&budget)
            .order(entry_fields::date.asc())
            .load::<Entry>(&mut *(self.get_connection()?).borrow_mut())?;

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
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<OutputBudget>, DaoError> {
        let query = "SELECT budgets.* FROM user_budgets, budgets \
                     WHERE user_budgets.user_id = $1 \
                     AND user_budgets.budget_id = budgets.id \
	             ORDER BY budgets.start_date";

        let loaded_budgets = sql_query(query)
            .bind::<sql_types::Uuid, _>(user_id)
            .load::<Budget>(&mut *(self.get_connection()?).borrow_mut())?;
        let mut loaded_categories = Category::belonging_to(&loaded_budgets)
            .order(category_fields::id.asc())
            .load::<Category>(&mut *(self.get_connection()?).borrow_mut())?
            .grouped_by(&loaded_budgets)
            .into_iter();
        let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
            .order(entry_fields::date.asc())
            .load::<Entry>(&mut *(self.get_connection()?).borrow_mut())?
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
        &mut self,
        user_id: Uuid,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<Vec<OutputBudget>, DaoError> {
        let query = "SELECT budgets.* FROM user_budgets, budgets \
                     WHERE user_budgets.user_id = $1 \
                     AND user_budgets.budget_id = budgets.id \
                     AND budgets.end_date >= $2 \
                     AND budgets.start_date <= $3 \
                     ORDER BY budgets.start_date";

        let loaded_budgets = sql_query(query)
            .bind::<sql_types::Uuid, _>(user_id)
            .bind::<sql_types::Date, _>(start_date)
            .bind::<sql_types::Date, _>(end_date)
            .load::<Budget>(&mut *(self.get_connection()?).borrow_mut())?;
        let mut loaded_categories = Category::belonging_to(&loaded_budgets)
            .order(category_fields::id.asc())
            .load::<Category>(&mut *(self.get_connection()?).borrow_mut())?
            .grouped_by(&loaded_budgets)
            .into_iter();
        let mut loaded_entries = Entry::belonging_to(&loaded_budgets)
            .order(entry_fields::date.asc())
            .load::<Entry>(&mut *(self.get_connection()?).borrow_mut())?
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
        &mut self,
        user_id: Uuid,
        budget_id: Uuid,
    ) -> Result<bool, DaoError> {
        let association_exists = match user_budgets
            .filter(user_budget_fields::user_id.eq(user_id))
            .filter(user_budget_fields::budget_id.eq(budget_id))
            .execute(&mut *(self.get_connection()?).borrow_mut())
        {
            Ok(count) => count > 0,
            Err(e) => {
                if e == diesel::result::Error::NotFound {
                    false
                } else {
                    return Err(e.into());
                }
            }
        };

        Ok(association_exists)
    }

    pub fn create_budget(
        &mut self,
        budget_data: &web::Json<InputBudget>,
        user_id: Uuid,
    ) -> Result<OutputBudget, DaoError> {
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
            .get_result::<Budget>(&mut *(self.get_connection()?).borrow_mut())?;

        let new_user_budget_association = NewUserBudget {
            created_timestamp: current_time,
            user_id,
            budget_id,
        };

        dsl::insert_into(user_budgets)
            .values(&new_user_budget_association)
            .execute(&mut *(self.get_connection()?).borrow_mut())?;

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
            .get_results::<Category>(&mut *(self.get_connection()?).borrow_mut())?;

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
        &mut self,
        edited_budget_data: &web::Json<InputEditBudget>,
        user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::sql_query(
            "UPDATE budgets AS b \
             SET modified_timestamp = $1, \
             name = $2, \
             description = $3, \
             start_date = $4, \
             end_date = $5 \
             FROM user_budgets AS ub \
             WHERE ub.user_id = $6 \
             AND b.id = ub.budget_id \
             AND b.id = $7",
        )
        .bind::<Timestamp, _>(chrono::Utc::now().naive_utc())
        .bind::<VarChar, _>(&edited_budget_data.name)
        .bind::<Nullable<Text>, _>(&edited_budget_data.description)
        .bind::<Date, _>(&edited_budget_data.start_date)
        .bind::<Date, _>(&edited_budget_data.end_date)
        .bind::<sql_types::Uuid, _>(user_id)
        .bind::<sql_types::Uuid, _>(&edited_budget_data.id)
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn invite_user(
        &mut self,
        budget_id: Uuid,
        recipient_user_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        let budget_share_event = NewBudgetShareEvent {
            id: Uuid::new_v4(),
            recipient_user_id,
            sender_user_id,
            budget_id,
            accepted: false,
            created_timestamp: chrono::Utc::now().naive_utc(),
            accepted_declined_timestamp: None,
        };

        Ok(dsl::insert_into(budget_share_events)
            .values(&budget_share_event)
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn delete_invitation(
        &mut self,
        invitation_id: Uuid,
        sender_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            budget_share_events
                .find(invitation_id)
                .filter(budget_share_event_fields::sender_user_id.eq(sender_user_id)),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn mark_invitation_accepted(
        &mut self,
        invitation_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<BudgetShareEvent, DaoError> {
        Ok(diesel::update(
            budget_share_events
                .find(invitation_id)
                .filter(budget_share_event_fields::recipient_user_id.eq(recipient_user_id)),
        )
        .set((
            budget_share_event_fields::accepted.eq(true),
            budget_share_event_fields::accepted_declined_timestamp
                .eq(chrono::Utc::now().naive_utc()),
        ))
        .get_result(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn mark_invitation_declined(
        &mut self,
        invitation_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<usize, DaoError> {
        Ok(diesel::update(
            budget_share_events
                .find(invitation_id)
                .filter(budget_share_event_fields::recipient_user_id.eq(recipient_user_id)),
        )
        .set((
            budget_share_event_fields::accepted.eq(false),
            budget_share_event_fields::accepted_declined_timestamp
                .eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_all_pending_invitations_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BudgetShareEvent>, DaoError> {
        Ok(budget_share_events
            .filter(budget_share_event_fields::recipient_user_id.eq(user_id))
            .filter(budget_share_event_fields::accepted_declined_timestamp.is_null())
            .order(budget_share_event_fields::created_timestamp.asc())
            .load::<BudgetShareEvent>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_all_pending_invitations_made_by_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<BudgetShareEvent>, DaoError> {
        Ok(budget_share_events
            .filter(budget_share_event_fields::sender_user_id.eq(user_id))
            .filter(budget_share_event_fields::accepted_declined_timestamp.is_null())
            .order(budget_share_event_fields::created_timestamp.asc())
            .load::<BudgetShareEvent>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn get_invitation(
        &mut self,
        invitation_id: Uuid,
        user_id: Uuid,
    ) -> Result<BudgetShareEvent, DaoError> {
        Ok(budget_share_events
            .find(invitation_id)
            .filter(
                budget_share_event_fields::sender_user_id
                    .eq(user_id)
                    .or(budget_share_event_fields::recipient_user_id.eq(user_id)),
            )
            .first::<BudgetShareEvent>(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn add_user(&mut self, budget_id: Uuid, user_id: Uuid) -> Result<usize, DaoError> {
        let current_time = chrono::Utc::now().naive_utc();

        let new_user_budget_association = NewUserBudget {
            created_timestamp: current_time,
            user_id,
            budget_id,
        };

        Ok(dsl::insert_into(user_budgets)
            .values(&new_user_budget_association)
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn remove_user(&mut self, budget_id: Uuid, user_id: Uuid) -> Result<usize, DaoError> {
        Ok(diesel::delete(
            user_budgets
                .filter(user_budget_fields::user_id.eq(user_id))
                .filter(user_budget_fields::budget_id.eq(budget_id)),
        )
        .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn count_users_remaining_in_budget(&mut self, budget_id: Uuid) -> Result<usize, DaoError> {
        Ok(user_budgets
            .filter(user_budget_fields::budget_id.eq(budget_id))
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn delete_budget(&mut self, budget_id: Uuid) -> Result<usize, DaoError> {
        Ok(diesel::delete(budgets.find(budget_id))
            .execute(&mut *(self.get_connection()?).borrow_mut())?)
    }

    pub fn create_entry(
        &mut self,
        entry_data: &web::Json<InputEntry>,
        user_id: Uuid,
    ) -> Result<Entry, DaoError> {
        let current_time = chrono::Utc::now().naive_utc();
        let entry_id = Uuid::new_v4();

        let name = entry_data.name.as_deref();
        let note = entry_data.note.as_deref();

        let new_entry = NewEntry {
            id: entry_id,
            budget_id: entry_data.budget_id,
            user_id,
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
            .get_result::<Entry>(&mut *(self.get_connection()?).borrow_mut())?;
        diesel::update(budgets.find(new_entry.budget_id))
            .set(budget_fields::latest_entry_time.eq(current_time))
            .execute(&mut *(self.get_connection()?).borrow_mut())?;

        Ok(entry)
    }
}
