use diesel::associations::GroupedBy;
use diesel::sql_types::{self, Timestamp, VarChar};
use diesel::{
    dsl, sql_query, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, JoinOnDsl,
    NullableExpressionMethods, QueryDsl, RunQueryDsl,
};
use std::time::SystemTime;
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::budget::{Budget, NewBudget};
use crate::models::budget_share_invite::{BudgetShareInvite, NewBudgetShareInvite};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::models::tombstone::NewTombstone;
use crate::models::user_budget::NewUserBudget;
use crate::request_io::{
    InputBudget, InputCategory, InputEditBudget, InputEditCategory, InputEntry,
    InputEntryAndCategory, OutputBudget, OutputBudgetFrame, OutputBudgetFrameCategory,
    OutputBudgetIdAndEncryptionKey, OutputBudgetShareInviteWithoutKey, OutputEntryIdAndCategoryId,
};
use crate::schema::budget_share_invites as budget_share_invite_fields;
use crate::schema::budget_share_invites::dsl::budget_share_invites;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::entries as entry_fields;
use crate::schema::entries::dsl::entries;
use crate::schema::tombstones as tombstone_fields;
use crate::schema::tombstones::dsl::tombstones;
use crate::schema::user_budgets as user_budget_fields;
use crate::schema::user_budgets::dsl::user_budgets;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn get_budget_by_id(
        &mut self,
        budget_id: Uuid,
        user_id: Uuid,
    ) -> Result<OutputBudget, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budget = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let budget = budgets
                    .select(budget_fields::all_columns)
                    .left_join(user_budgets.on(user_budget_fields::budget_id.eq(budget_id)))
                    .filter(budget_fields::id.eq(budget_id))
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .get_result::<Budget>(conn)?;
                let loaded_categories = Category::belonging_to(&budget).load::<Category>(conn)?;
                let loaded_entries = Entry::belonging_to(&budget).load::<Entry>(conn)?;

                Ok(OutputBudget {
                    id: budget.id,
                    encrypted_blob: budget.encrypted_blob,
                    modified_timestamp: budget.modified_timestamp,
                    categories: loaded_categories,
                    entries: loaded_entries,
                })
            })?;

        Ok(output_budget)
    }

    pub fn get_multiple_budgets_by_id(
        &mut self,
        budget_ids: Vec<Uuid>,
        user_id: Uuid,
    ) -> Result<Vec<OutputBudget>, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budgets = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let loaded_budgets = budgets
                    .select(budget_fields::all_columns)
                    .left_join(user_budgets.on(user_budget_fields::budget_id.eq(budget_fields::id)))
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(budget_fields::id.eq_any(budget_ids))
                    .get_results::<Budget>(conn)?;
                let loaded_categories = Category::belonging_to(&loaded_budgets)
                    .load::<Category>(conn)?
                    .grouped_by(&loaded_budgets);
                let loaded_entries = Entry::belonging_to(&loaded_budgets)
                    .load::<Entry>(conn)?
                    .grouped_by(&loaded_budgets);

                let zipped_budgets = loaded_budgets
                    .into_iter()
                    .zip(loaded_categories.into_iter())
                    .zip(loaded_entries.into_iter());
                let mut output_budgets = Vec::new();

                for ((budget, budget_categories), budget_entries) in zipped_budgets {
                    let output_budget = OutputBudget {
                        id: budget.id,
                        encrypted_blob: budget.encrypted_blob,
                        modified_timestamp: budget.modified_timestamp,
                        categories: budget_categories,
                        entries: budget_entries,
                    };

                    output_budgets.push(output_budget);
                }

                Ok(output_budgets)
            })?;

        Ok(output_budgets)
    }

    pub fn get_all_budgets_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<OutputBudget>, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budgets = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let loaded_budgets = budgets
                    .select(budget_fields::all_columns)
                    .left_join(user_budgets.on(user_budget_fields::budget_id.eq(budget_fields::id)))
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .get_results::<Budget>(conn)?;
                let loaded_categories = Category::belonging_to(&loaded_budgets)
                    .load::<Category>(conn)?
                    .grouped_by(&loaded_budgets);
                let loaded_entries = Entry::belonging_to(&loaded_budgets)
                    .load::<Entry>(conn)?
                    .grouped_by(&loaded_budgets);

                let zipped_budgets = loaded_budgets
                    .into_iter()
                    .zip(loaded_categories.into_iter())
                    .zip(loaded_entries.into_iter());
                let mut output_budgets = Vec::new();

                for ((budget, budget_categories), budget_entries) in zipped_budgets {
                    let output_budget = OutputBudget {
                        id: budget.id,
                        encrypted_blob: budget.encrypted_blob,
                        modified_timestamp: budget.modified_timestamp,
                        categories: budget_categories,
                        entries: budget_entries,
                    };

                    output_budgets.push(output_budget);
                }

                Ok(output_budgets)
            })?;

        Ok(output_budgets)
    }

    pub fn create_budget(
        &mut self,
        budget_data: &InputBudget,
        user_id: Uuid,
    ) -> Result<OutputBudgetFrame, DaoError> {
        let current_time = SystemTime::now();
        let budget_id = Uuid::new_v4();

        let new_budget = NewBudget {
            id: budget_id,
            encrypted_blob: &budget_data.encrypted_blob_b64,
            modified_timestamp: current_time,
        };

        let new_user_budget_association = NewUserBudget {
            user_id,
            budget_id,
            encryption_key_encrypted: &budget_data.encryption_key_encrypted_b64,
            encryption_key_is_encrypted_with_aes_not_rsa: true,
            modified_timestamp: current_time,
        };

        let mut budget_categories = Vec::new();
        let mut budget_category_temp_ids = Vec::new();

        for category in &budget_data.categories {
            let new_category = NewCategory {
                budget_id,
                id: Uuid::new_v4(),
                encrypted_blob: &category.encrypted_blob_b64,
                modified_timestamp: current_time,
            };

            budget_categories.push(new_category);
            budget_category_temp_ids.push(category.temp_id);
        }

        let mut output_budget = OutputBudgetFrame {
            id: budget_id,
            categories: Vec::with_capacity(budget_categories.len()),
            modified_timestamp: current_time,
        };

        for i in 0..budget_categories.len() {
            let category_frame = OutputBudgetFrameCategory {
                temp_id: budget_category_temp_ids[i],
                real_id: budget_categories[i].id,
            };

            output_budget.categories.push(category_frame);
        }

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(budgets)
                    .values(&new_budget)
                    .execute(conn)?;

                dsl::insert_into(categories)
                    .values(budget_categories)
                    .execute(conn)?;

                dsl::insert_into(user_budgets)
                    .values(&new_user_budget_association)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(output_budget)
    }

    pub fn update_budget(
        &mut self,
        budget_id: Uuid,
        edited_budget_data: &str,
        user_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::sql_query(
            "UPDATE budgets AS b \
             SET modified_timestamp = $1, \
             encrypted_blob = $2 \
             FROM user_budgets AS ub \
             WHERE ub.user_id = $3 \
             AND b.id = ub.budget_id \
             AND b.id = $4",
        )
        .bind::<Timestamp, _>(SystemTime::now())
        .bind::<VarChar, _>(edited_budget_data)
        .bind::<sql_types::Uuid, _>(user_id)
        .bind::<sql_types::Uuid, _>(budget_id)
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn invite_user(
        &mut self,
        budget_id: Uuid,
        budget_name_encrypted: &str,
        recipient_user_id: Uuid,
        sender_user_id: Uuid,
        sender_name_encrypted: Option<&str>,
        encryption_key_encrypted: &str,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                let is_sender_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(sender_user_id))
                    .filter(user_budget_fields::budget_id.eq(budget_id))
                    .count()
                    .execute(conn)?
                    != 0;

                if !is_sender_in_budget {
                    return Err(DaoError::QueryFailure(diesel::result::Error::NotFound));
                }

                let is_recipient_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(recipient_user_id))
                    .filter(user_budget_fields::budget_id.eq(budget_id))
                    .count()
                    .execute(conn)?
                    != 0;

                if is_recipient_in_budget {
                    return Err(DaoError::WontRunQuery);
                }

                let budget_share_invite = NewBudgetShareInvite {
                    id: Uuid::new_v4(),
                    recipient_user_id,
                    sender_user_id,
                    budget_id,
                    budget_name_encrypted,
                    sender_name_encrypted,
                    encryption_key_encrypted,
                };

                dsl::insert_into(budget_share_invites)
                    .values(&budget_share_invite)
                    .on_conflict((
                        budget_share_invite_fields::recipient_user_id,
                        budget_share_invite_fields::sender_user_id,
                        budget_share_invite_fields::budget_id,
                    ))
                    .do_update()
                    .set((
                        budget_share_invite_fields::budget_name_encrypted.eq(budget_name_encrypted),
                        budget_share_invite_fields::sender_name_encrypted.eq(sender_name_encrypted),
                        budget_share_invite_fields::encryption_key_encrypted
                            .eq(encryption_key_encrypted),
                    ))
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn delete_invitation(
        &mut self,
        invitation_id: Uuid,
        sender_or_recipient_user_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::delete(
            budget_share_invites.find(invitation_id).filter(
                budget_share_invite_fields::sender_user_id
                    .eq(sender_or_recipient_user_id)
                    .or(budget_share_invite_fields::recipient_user_id
                        .eq(sender_or_recipient_user_id)),
            ),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn accept_invitation(
        &mut self,
        invitation_id: Uuid,
        recipient_user_id: Uuid,
    ) -> Result<OutputBudgetIdAndEncryptionKey, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let budget_id_and_key = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let budget_id_and_key =
                    diesel::delete(budget_share_invites.find(invitation_id).filter(
                        budget_share_invite_fields::recipient_user_id.eq(recipient_user_id),
                    ))
                    .returning((
                        budget_share_invite_fields::budget_id,
                        budget_share_invite_fields::encryption_key_encrypted,
                    ))
                    .get_result::<OutputBudgetIdAndEncryptionKey>(conn)?;

                let user_budget_relation = NewUserBudget {
                    user_id: recipient_user_id,
                    budget_id: budget_id_and_key.budget_id,
                    encryption_key_encrypted: &budget_id_and_key.encryption_key_encrypted,
                    encryption_key_is_encrypted_with_aes_not_rsa: false,
                    modified_timestamp: SystemTime::now(),
                };

                dsl::insert_into(user_budgets)
                    .values(&user_budget_relation)
                    .execute(conn)?;

                Ok(budget_id_and_key)
            })?;

        Ok(budget_id_and_key)
    }

    pub fn get_all_pending_invitations_for_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<OutputBudgetShareInviteWithoutKey>, DaoError> {
        Ok(budget_share_invites
            .select((
                budget_share_invite_fields::id,
                budget_share_invite_fields::recipient_user_id,
                budget_share_invite_fields::sender_user_id,
                budget_share_invite_fields::budget_id,
                budget_share_invite_fields::budget_name_encrypted,
                budget_share_invite_fields::sender_name_encrypted,
            ))
            .filter(budget_share_invite_fields::recipient_user_id.eq(user_id))
            .load::<OutputBudgetShareInviteWithoutKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_all_pending_invitations_made_by_user(
        &mut self,
        user_id: Uuid,
    ) -> Result<Vec<OutputBudgetShareInviteWithoutKey>, DaoError> {
        Ok(budget_share_invites
            .select((
                budget_share_invite_fields::id,
                budget_share_invite_fields::recipient_user_id,
                budget_share_invite_fields::sender_user_id,
                budget_share_invite_fields::budget_id,
                budget_share_invite_fields::budget_name_encrypted,
                budget_share_invite_fields::sender_name_encrypted,
            ))
            .filter(budget_share_invite_fields::sender_user_id.eq(user_id))
            .load::<OutputBudgetShareInviteWithoutKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_invitation(
        &mut self,
        invitation_id: Uuid,
        user_id: Uuid,
    ) -> Result<OutputBudgetShareInviteWithoutKey, DaoError> {
        Ok(budget_share_invites
            .select((
                budget_share_invite_fields::id,
                budget_share_invite_fields::recipient_user_id,
                budget_share_invite_fields::sender_user_id,
                budget_share_invite_fields::budget_id,
                budget_share_invite_fields::budget_name_encrypted,
                budget_share_invite_fields::sender_name_encrypted,
            ))
            .find(invitation_id)
            .filter(
                budget_share_invite_fields::sender_user_id
                    .eq(user_id)
                    .or(budget_share_invite_fields::recipient_user_id.eq(user_id)),
            )
            .get_result::<OutputBudgetShareInviteWithoutKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn leave_budget(&mut self, budget_id: Uuid, user_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                diesel::delete(
                    user_budgets
                        .filter(user_budget_fields::user_id.eq(user_id))
                        .filter(user_budget_fields::budget_id.eq(budget_id)),
                )
                .execute(conn)?;

                let users_remaining_in_budget = user_budgets
                    .filter(user_budget_fields::budget_id.eq(budget_id))
                    .execute(conn)?;

                if users_remaining_in_budget == 0 {
                    diesel::delete(budgets.find(budget_id)).execute(conn)?;
                }

                Ok(())
            })?;

        Ok(())
    }

    pub fn create_entry(
        &mut self,
        entry_data: &InputEntry,
        user_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let entry_id = Uuid::new_v4();

        let new_entry = NewEntry {
            id: entry_id,
            budget_id: entry_data.budget_id,
            encrypted_blob: &entry_data.encrypted_blob_b64,
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(user_budget_fields::budget_id.eq(entry_data.budget_id))
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    dsl::insert_into(entries).values(&new_entry).execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(entry_id)
    }

    pub fn create_entry_and_category(
        &mut self,
        entry_and_category_data: &InputEntryAndCategory,
        user_id: Uuid,
    ) -> Result<OutputEntryIdAndCategoryId, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        let new_entry = NewEntry {
            id: entry_id,
            budget_id: entry_and_category_data.budget_id,
            encrypted_blob: &entry_and_category_data.entry_encrypted_blob_b64,
            modified_timestamp: current_time,
        };

        let new_category = NewCategory {
            id: category_id,
            budget_id: entry_and_category_data.budget_id,
            encrypted_blob: &entry_and_category_data.category_encrypted_blob_b64,
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(user_budget_fields::budget_id.eq(entry_and_category_data.budget_id))
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    dsl::insert_into(entries).values(&new_entry).execute(conn)?;

                    dsl::insert_into(categories)
                        .values(&new_category)
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(OutputEntryIdAndCategoryId {
            entry_id,
            category_id,
        })
    }

    pub fn update_entry(
        &mut self,
        entry_id: Uuid,
        entry_encrypted_blob: &str,
        user_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(
                        user_budget_fields::budget_id.nullable().eq(entries
                            .select(entry_fields::budget_id)
                            .find(entry_id)
                            .single_value()),
                    )
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    diesel::update(entries.find(entry_id))
                        .set((
                            entry_fields::encrypted_blob.eq(entry_encrypted_blob),
                            entry_fields::modified_timestamp.eq(SystemTime::now()),
                        ))
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(())
    }

    pub fn delete_entry(&mut self, entry_id: Uuid, user_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(
                        user_budget_fields::budget_id.nullable().eq(entries
                            .select(entry_fields::budget_id)
                            .find(entry_id)
                            .single_value()),
                    )
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    diesel::delete(entries.find(entry_id)).execute(conn)?;

                    let new_tombstone = NewTombstone {
                        item_id: entry_id,
                        related_user_id: user_id,
                        origin_table: "entries",
                        deletion_timestamp: SystemTime::now(),
                    };

                    dsl::insert_into(tombstones)
                        .values(&new_tombstone)
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(())
    }

    pub fn create_category(
        &mut self,
        category_data: &InputCategory,
        user_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();

        let new_category = NewCategory {
            id: category_id,
            budget_id: category_data.budget_id,
            encrypted_blob: &category_data.encrypted_blob_b64,
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(user_budget_fields::budget_id.eq(category_data.budget_id))
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    dsl::insert_into(categories)
                        .values(&new_category)
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(category_id)
    }

    pub fn update_category(
        &mut self,
        category_id: Uuid,
        category_encrypted_blob: &str,
        user_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(
                        user_budget_fields::budget_id.nullable().eq(categories
                            .select(category_fields::budget_id)
                            .find(category_id)
                            .single_value()),
                    )
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    diesel::update(categories.find(category_id))
                        .set((
                            category_fields::encrypted_blob.eq(category_encrypted_blob),
                            category_fields::modified_timestamp.eq(SystemTime::now()),
                        ))
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(())
    }

    pub fn delete_category(&mut self, category_id: Uuid, user_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let is_user_in_budget = user_budgets
                    .filter(user_budget_fields::user_id.eq(user_id))
                    .filter(
                        user_budget_fields::budget_id.nullable().eq(categories
                            .select(category_fields::budget_id)
                            .find(category_id)
                            .single_value()),
                    )
                    .count()
                    .execute(conn)?
                    != 0;

                if is_user_in_budget {
                    diesel::delete(categories.find(category_id)).execute(conn)?;

                    let new_tombstone = NewTombstone {
                        item_id: category_id,
                        related_user_id: user_id,
                        origin_table: "categories",
                        deletion_timestamp: SystemTime::now(),
                    };

                    dsl::insert_into(tombstones)
                        .values(&new_tombstone)
                        .execute(conn)?;

                    Ok(())
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            })?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use diesel::ExpressionMethods;
    use rand::prelude::*;
    use std::time::Duration;

    use crate::db::user;
    use crate::models::budget::Budget;
    use crate::models::category::Category;
    use crate::models::user::User;
    use crate::models::user_budget::UserBudget;
    use crate::password_hasher;
    use crate::request_io::{InputBudget, InputCategory, InputUser, OutputBudget};
    use crate::schema::budget_share_invites as budget_share_invite_fields;
    use crate::schema::budget_share_invites::dsl::budget_share_invites;
    use crate::schema::budgets::dsl::budgets;
    use crate::schema::categories as category_fields;
    use crate::schema::categories::dsl::categories;
    use crate::schema::entries as entry_fields;
    use crate::schema::user_budgets as user_budget_fields;
    use crate::schema::user_budgets::dsl::user_budgets;
    use crate::test_env;

    pub struct UserAndBudget {
        user: User,
        budget: OutputBudget,
    }

    pub fn generate_user_and_budget() -> Result<UserAndBudget, DaoError> {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;

        let budget_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let created_user = user::tests::generate_user()?;

        let category0 = InputCategory {
            name: format!("First Random Category {budget_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            name: format!("Second Random Category {budget_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {budget_number}"),
            description: Some(format!(
                "This is a description of Test Budget {budget_number}.",
            )),
            categories: budget_categories,
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let created_budget =
            Dao::new(db_thread_pool).create_budget(&new_budget, created_user.id)?;

        Ok(UserAndBudget {
            user: created_user,
            budget: created_budget,
        })
    }

    #[test]
    fn test_create_budget() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", user_number),
            password: String::from("g&eWi3#oIKDW%cTu*5*2"),
            first_name: format!("Test-{}", user_number),
            last_name: format!("User-{}", user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let hash_params = password_hasher::HashParams {
            salt_len: 16,
            hash_len: 32,
            hash_iterations: 2,
            hash_mem_size_kib: 128,
            hash_lanes: 2,
        };

        let created_user = user::Dao::new(db_thread_pool)
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let category0 = InputCategory {
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
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
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        dao.create_budget(&new_budget, created_user.id).unwrap();

        let mut db_connection = db_thread_pool.get().unwrap();
        let created_user_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(created_user_budget_associations.len(), 1);
        assert!(created_user_budget_associations[0].created_timestamp < SystemTime::now());
        assert_eq!(created_user_budget_associations[0].user_id, created_user.id);

        let budget_id = created_user_budget_associations[0].budget_id;
        let budget = budgets
            .find(budget_id)
            .first::<Budget>(&mut db_connection)
            .unwrap();

        assert_eq!(budget.name, new_budget.name);
        assert_eq!(budget.description, new_budget.description);
        assert_eq!(budget.start_date, new_budget.start_date);
        assert_eq!(budget.end_date, new_budget.end_date);

        let saved_categories = categories
            .filter(category_fields::budget_id.eq(budget_id))
            .order(category_fields::name.asc())
            .load::<Category>(&mut db_connection)
            .unwrap();

        assert_eq!(saved_categories[0].name, budget_categories[0].name);
        assert_eq!(
            saved_categories[0].limit_cents,
            budget_categories[0].limit_cents
        );
        assert_eq!(saved_categories[0].color, budget_categories[0].color);
    }

    #[test]
    fn test_invite_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 0);

        dao.invite_user(budget.id, created_user2.id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        assert_eq!(
            created_budget_share_invites[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_budget_share_invites[0].sender_user_id,
            created_user1.id
        );
        assert_eq!(created_budget_share_invites[0].budget_id, budget.id);
        assert!(!created_budget_share_invites[0].accepted);

        assert!(created_budget_share_invites[0].created_timestamp < SystemTime::now());
        assert_eq!(
            created_budget_share_invites[0].accepted_declined_timestamp,
            None
        );
    }

    #[test]
    fn test_delete_invitation() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;
        dao.invite_user(budget.id, created_user2.id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        dao.delete_invitation(created_budget_share_invites[0].id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 0);
    }

    #[test]
    fn test_mark_invitation_accepted() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        dao.invite_user(budget.id, created_user2.id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        let returned_budget_share_invite = dao
            .mark_invitation_accepted(created_budget_share_invites[0].id, created_user2.id)
            .unwrap();

        assert_eq!(returned_budget_share_invite.budget_id, budget.id);

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        assert_eq!(
            created_budget_share_invites[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_budget_share_invites[0].sender_user_id,
            created_user1.id
        );
        assert_eq!(created_budget_share_invites[0].budget_id, budget.id);
        assert!(created_budget_share_invites[0].accepted);

        assert!(created_budget_share_invites[0].created_timestamp < SystemTime::now());
        assert!(
            created_budget_share_invites[0]
                .accepted_declined_timestamp
                .unwrap()
                < SystemTime::now()
        );
        assert!(
            created_budget_share_invites[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_budget_share_invites[0].created_timestamp
        );
    }

    #[test]
    fn test_mark_invitation_declined() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        dao.invite_user(budget.id, created_user2.id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        dao.mark_invitation_declined(created_budget_share_invites[0].id, created_user2.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        assert_eq!(
            created_budget_share_invites[0].recipient_user_id,
            created_user2.id
        );
        assert_eq!(
            created_budget_share_invites[0].sender_user_id,
            created_user1.id
        );
        assert_eq!(created_budget_share_invites[0].budget_id, budget.id);
        assert!(!created_budget_share_invites[0].accepted);

        assert!(created_budget_share_invites[0].created_timestamp < SystemTime::now());
        assert!(
            created_budget_share_invites[0]
                .accepted_declined_timestamp
                .unwrap()
                < SystemTime::now()
        );
        assert!(
            created_budget_share_invites[0]
                .accepted_declined_timestamp
                .unwrap()
                > created_budget_share_invites[0].created_timestamp
        );
    }

    #[test]
    fn test_get_all_pending_invitations_for_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user.clone();

        let budget1 = created_user_and_budget1.budget;
        let budget2 = created_user_and_budget2.budget;

        dao.invite_user(budget1.id, created_user2.id, created_user1.id)
            .unwrap();

        dao.invite_user(budget2.id, created_user2.id, created_user1.id)
            .unwrap();

        let share_invites = dao
            .get_all_pending_invitations_for_user(created_user1.id)
            .unwrap();

        assert_eq!(share_invites.len(), 0);

        let share_invites = dao
            .get_all_pending_invitations_for_user(created_user2.id)
            .unwrap();

        assert_eq!(share_invites.len(), 2);

        assert_eq!(share_invites[0].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[0].sender_user_id, created_user1.id);
        assert_eq!(share_invites[0].budget_id, budget1.id);
        assert!(!share_invites[0].accepted);

        assert!(share_invites[0].created_timestamp < SystemTime::now());
        assert!(share_invites[0].accepted_declined_timestamp.is_none());

        assert_eq!(share_invites[1].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[1].sender_user_id, created_user1.id);
        assert_eq!(share_invites[1].budget_id, budget2.id);
        assert!(!share_invites[1].accepted);

        assert!(share_invites[1].created_timestamp < SystemTime::now());
        assert!(share_invites[1].accepted_declined_timestamp.is_none());

        dao.mark_invitation_accepted(share_invites[0].id, created_user2.id)
            .unwrap();

        let share_invites = dao
            .get_all_pending_invitations_for_user(created_user2.id)
            .unwrap();

        assert_eq!(share_invites.len(), 1);

        assert_eq!(share_invites[0].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[0].sender_user_id, created_user1.id);
        assert_eq!(share_invites[0].budget_id, budget2.id);
        assert!(!share_invites[0].accepted);

        assert!(share_invites[0].created_timestamp < SystemTime::now());
        assert!(share_invites[0].accepted_declined_timestamp.is_none());
    }

    #[test]
    fn test_get_all_pending_invitations_made_by_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user.clone();

        let budget1 = created_user_and_budget1.budget;
        let budget2 = created_user_and_budget2.budget;

        dao.invite_user(budget1.id, created_user2.id, created_user1.id)
            .unwrap();

        dao.invite_user(budget2.id, created_user2.id, created_user1.id)
            .unwrap();

        let share_invites = dao
            .get_all_pending_invitations_made_by_user(created_user2.id)
            .unwrap();

        assert_eq!(share_invites.len(), 0);

        let share_invites = dao
            .get_all_pending_invitations_made_by_user(created_user1.id)
            .unwrap();

        assert_eq!(share_invites.len(), 2);

        assert_eq!(share_invites[0].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[0].sender_user_id, created_user1.id);
        assert_eq!(share_invites[0].budget_id, budget1.id);
        assert!(!share_invites[0].accepted);

        assert!(share_invites[0].created_timestamp < SystemTime::now());
        assert!(share_invites[0].accepted_declined_timestamp.is_none());

        assert_eq!(share_invites[1].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[1].sender_user_id, created_user1.id);
        assert_eq!(share_invites[1].budget_id, budget2.id);
        assert!(!share_invites[1].accepted);

        assert!(share_invites[1].created_timestamp < SystemTime::now());
        assert!(share_invites[1].accepted_declined_timestamp.is_none());

        dao.mark_invitation_declined(share_invites[0].id, created_user2.id)
            .unwrap();

        let share_invites = dao
            .get_all_pending_invitations_made_by_user(created_user1.id)
            .unwrap();

        assert_eq!(share_invites.len(), 1);

        assert_eq!(share_invites[0].recipient_user_id, created_user2.id);
        assert_eq!(share_invites[0].sender_user_id, created_user1.id);
        assert_eq!(share_invites[0].budget_id, budget2.id);
        assert!(!share_invites[0].accepted);

        assert!(share_invites[0].created_timestamp < SystemTime::now());
        assert!(share_invites[0].accepted_declined_timestamp.is_none());
    }

    #[test]
    fn test_get_invitation() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        dao.invite_user(budget.id, created_user2.id, created_user1.id)
            .unwrap();

        let created_budget_share_invites = budget_share_invites
            .filter(budget_share_invite_fields::recipient_user_id.eq(created_user2.id))
            .filter(budget_share_invite_fields::sender_user_id.eq(created_user1.id))
            .load::<BudgetShareInvite>(&mut db_connection)
            .unwrap();

        assert_eq!(created_budget_share_invites.len(), 1);

        dao.mark_invitation_accepted(created_budget_share_invites[0].id, created_user2.id)
            .unwrap();

        let share_invite = dao
            .get_invitation(created_budget_share_invites[0].id, created_user1.id)
            .unwrap();

        assert_eq!(share_invite.recipient_user_id, created_user2.id);
        assert_eq!(share_invite.sender_user_id, created_user1.id);
        assert_eq!(share_invite.budget_id, budget.id);
        assert!(share_invite.accepted);

        assert!(share_invite.created_timestamp < SystemTime::now());
        assert!(share_invite.accepted_declined_timestamp.unwrap() < SystemTime::now());
        assert!(share_invite.accepted_declined_timestamp.unwrap() > share_invite.created_timestamp);

        let share_invite = dao
            .get_invitation(created_budget_share_invites[0].id, created_user2.id)
            .unwrap();

        assert_eq!(share_invite.recipient_user_id, created_user2.id);
        assert_eq!(share_invite.sender_user_id, created_user1.id);
        assert_eq!(share_invite.budget_id, budget.id);
        assert!(share_invite.accepted);

        assert!(share_invite.created_timestamp < SystemTime::now());
        assert!(share_invite.accepted_declined_timestamp.unwrap() < SystemTime::now());
        assert!(share_invite.accepted_declined_timestamp.unwrap() > share_invite.created_timestamp);
    }

    #[test]
    fn test_add_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        dao.add_user(budget.id, created_user2.id).unwrap();

        let created_user1_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user1.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        let created_user2_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(created_user1_budget_associations.len(), 1);
        assert_eq!(created_user2_budget_associations.len(), 2);

        let mut user2_budget_association: Option<UserBudget> = None;

        for assoc in created_user2_budget_associations {
            if assoc.budget_id == budget.id {
                user2_budget_association = Some(assoc);
                break;
            }
        }

        let user2_budget_association = user2_budget_association.unwrap();

        assert!(created_user1_budget_associations[0].created_timestamp < SystemTime::now());
        assert!(user2_budget_association.created_timestamp < SystemTime::now());

        assert_eq!(
            created_user1_budget_associations[0].user_id,
            created_user1.id
        );
        assert_eq!(user2_budget_association.user_id, created_user2.id);

        let query_user1 = format!(
            "SELECT budgets.* FROM user_budgets, budgets \
             WHERE user_budgets.user_id = '{}' \
             AND user_budgets.budget_id = budgets.id \
	     ORDER BY budgets.start_date",
            created_user1.id,
        );

        let query_user2 = format!(
            "SELECT budgets.* FROM user_budgets, budgets \
             WHERE user_budgets.user_id = '{}' \
             AND user_budgets.budget_id = budgets.id \
	     ORDER BY budgets.start_date",
            created_user2.id,
        );

        let user1_loaded_budgets = sql_query(query_user1)
            .load::<Budget>(&mut db_connection)
            .unwrap();
        let user2_loaded_budgets = sql_query(query_user2)
            .load::<Budget>(&mut db_connection)
            .unwrap();

        assert_eq!(user1_loaded_budgets.len(), 1);
        assert_eq!(user2_loaded_budgets.len(), 2);

        let mut budget_for_user2: Option<Budget> = None;

        for budg in user2_loaded_budgets {
            if budg.id == budget.id {
                budget_for_user2 = Some(budg);
                break;
            }
        }

        let budget_for_user1 = &user1_loaded_budgets[0];
        let budget_for_user2 = budget_for_user2.unwrap();

        assert_eq!(budget_for_user1.id, budget_for_user2.id);
        assert_eq!(budget_for_user1.name, budget_for_user2.name);
        assert_eq!(budget_for_user1.description, budget_for_user2.description);
        assert_eq!(budget_for_user1.start_date, budget_for_user2.start_date);
        assert_eq!(budget_for_user1.end_date, budget_for_user2.end_date);
    }

    #[test]
    fn test_remove_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user.clone();

        let budget1 = created_user_and_budget1.budget;
        let budget2 = created_user_and_budget2.budget;

        dao.add_user(budget1.id, created_user2.id).unwrap();
        dao.add_user(budget2.id, created_user1.id).unwrap();

        let created_user1_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user1.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        let created_user2_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(created_user1_budget_associations.len(), 2);
        assert_eq!(created_user2_budget_associations.len(), 2);

        let affected_row_count = dao.remove_user(budget2.id, created_user2.id).unwrap();
        assert_eq!(affected_row_count, 1);

        let created_user1_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user1.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        let created_user2_budget_associations = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2.id))
            .load::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(created_user1_budget_associations.len(), 2);
        assert_eq!(created_user2_budget_associations.len(), 1);

        let query_user1 = format!(
            "SELECT budgets.* FROM user_budgets, budgets \
             WHERE user_budgets.user_id = '{}' \
             AND user_budgets.budget_id = budgets.id \
	     ORDER BY budgets.start_date",
            created_user1.id,
        );

        let query_user2 = format!(
            "SELECT budgets.* FROM user_budgets, budgets \
             WHERE user_budgets.user_id = '{}' \
             AND user_budgets.budget_id = budgets.id \
	     ORDER BY budgets.start_date",
            created_user2.id,
        );

        let user1_loaded_budgets = sql_query(query_user1)
            .load::<Budget>(&mut db_connection)
            .unwrap();
        let user2_loaded_budgets = sql_query(query_user2)
            .load::<Budget>(&mut db_connection)
            .unwrap();

        assert_eq!(user1_loaded_budgets.len(), 2);
        assert_eq!(user2_loaded_budgets.len(), 1);

        let budget_ids_for_user1 = vec![user1_loaded_budgets[0].id, user1_loaded_budgets[1].id];
        let budget1_for_user2 = &user2_loaded_budgets[0];

        assert!(budget_ids_for_user1.contains(&budget1.id));
        assert!(budget_ids_for_user1.contains(&budget2.id));
        assert_eq!(budget1_for_user2.id, budget1.id);
    }

    #[test]
    fn test_count_users_remaining_in_budget() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget1 = generate_user_and_budget().unwrap();
        let created_user_and_budget2 = generate_user_and_budget().unwrap();

        let created_user1 = created_user_and_budget1.user.clone();
        let created_user2 = created_user_and_budget2.user;

        let budget = created_user_and_budget1.budget;

        let budget_user_count = dao.count_users_remaining_in_budget(budget.id).unwrap();
        assert_eq!(budget_user_count, 1);

        dao.add_user(budget.id, created_user2.id).unwrap();

        let budget_user_count = dao.count_users_remaining_in_budget(budget.id).unwrap();
        assert_eq!(budget_user_count, 2);

        dao.remove_user(budget.id, created_user2.id).unwrap();

        let budget_user_count = dao.count_users_remaining_in_budget(budget.id).unwrap();
        assert_eq!(budget_user_count, 1);

        dao.remove_user(budget.id, created_user1.id).unwrap();

        let budget_user_count = dao.count_users_remaining_in_budget(budget.id).unwrap();
        assert_eq!(budget_user_count, 0);
    }

    #[test]
    fn test_delete_budget() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let created_budget = created_user_and_budget.budget;

        dao.delete_budget(created_budget.id).unwrap();

        assert!(dao
            .get_budget_by_id(created_budget.id, created_user.id)
            .is_err());
    }

    #[test]
    fn test_edit_budget_one_field() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let budget_before = created_user_and_budget.budget;

        let budget_edits = InputEditBudget {
            id: budget_before.id,
            name: budget_before.name.clone(),
            description: None,
            start_date: budget_before.start_date,
            end_date: budget_before.end_date,
        };

        dao.edit_budget(&budget_edits, created_user.id).unwrap();

        let budget_after = dao
            .get_budget_by_id(budget_before.id, created_user.id)
            .unwrap();

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

    #[test]
    fn test_edit_budget_all_fields() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let budget_before = created_user_and_budget.budget;

        let budget_edits = InputEditBudget {
            id: budget_before.id,
            name: String::from("this is an edited budget name"),
            description: Some(String::from("This is an edited description for the budget")),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        dao.edit_budget(&budget_edits, created_user.id).unwrap();

        let budget_after = dao
            .get_budget_by_id(budget_before.id, created_user.id)
            .unwrap();

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

    #[test]
    fn test_edit_budget_start_date_cannot_be_after_end_date() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let budget_before = created_user_and_budget.budget;

        let budget_edits = InputEditBudget {
            id: budget_before.id,
            name: budget_before.name.clone(),
            description: budget_before.description.clone(),
            start_date: budget_before.end_date + Duration::from_secs(86400),
            end_date: budget_before.end_date,
        };

        let edit_result = dao.edit_budget(&budget_edits, created_user.id);

        assert!(edit_result.is_err());
    }

    #[test]
    fn test_create_entry() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);
        let mut db_connection = db_thread_pool.get().unwrap();

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let created_budget = created_user_and_budget.budget;

        let new_entry = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..900_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category_id: None,
            note: Some(String::from("This is a little note")),
        };

        let created_entry = dao.create_entry(&new_entry, created_user.id).unwrap();

        let entry = entries
            .filter(entry_fields::id.eq(created_entry.id))
            .first::<Entry>(&mut db_connection)
            .unwrap();

        assert_eq!(entry.amount_cents, new_entry.amount_cents);
        assert_eq!(entry.date, new_entry.date);
        assert_eq!(entry.name, new_entry.name);
        assert_eq!(entry.category_id, new_entry.category_id);
        assert_eq!(entry.note, new_entry.note);

        let fetched_budget = dao
            .get_budget_by_id(created_budget.id, created_user.id)
            .unwrap();

        assert!(fetched_budget.latest_entry_time > created_budget.latest_entry_time);
        assert_eq!(fetched_budget.entries.len(), 1);

        let fetched_budget_entry = &fetched_budget.entries[0];
        assert_eq!(fetched_budget_entry.amount_cents, new_entry.amount_cents);
        assert_eq!(fetched_budget_entry.date, new_entry.date);
        assert_eq!(fetched_budget_entry.name, new_entry.name);
        assert_eq!(fetched_budget_entry.category_id, new_entry.category_id);
        assert_eq!(fetched_budget_entry.note, new_entry.note);
    }

    #[test]
    fn test_get_budget_by_id() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let created_budget = created_user_and_budget.budget;

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..800_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category_id: None,
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(800_000_000..900_000_000)),
            name: None,
            category_id: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        dao.create_entry(&entry0, created_user.id).unwrap();
        dao.create_entry(&entry1, created_user.id).unwrap();

        let fetched_budget = dao
            .get_budget_by_id(created_budget.id, created_user.id)
            .unwrap();

        assert_eq!(fetched_budget.id, created_budget.id);
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

            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }

        assert!(!fetched_budget.entries.is_empty());
        assert_eq!(fetched_budget.entries.len(), created_entries.len());
        for (i, fetched_entry) in fetched_budget.entries.iter().enumerate() {
            let created_entry = &created_entries[i];

            assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
            assert_eq!(fetched_entry.date, created_entry.date);
            assert_eq!(fetched_entry.name, created_entry.name);
            assert_eq!(fetched_entry.category_id, created_entry.category_id);
            assert_eq!(fetched_entry.note, created_entry.note);
        }
    }

    #[test]
    fn test_get_all_budgets_for_user() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

        let created_user_and_budget = generate_user_and_budget().unwrap();
        let created_user = created_user_and_budget.user.clone();
        let budget0 = created_user_and_budget.budget;

        let category0 = InputCategory {
            name: "First Random Category user".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            name: "Second Random Category user".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget1_categories = vec![category0, category1];

        let new_budget1 = InputBudget {
            name: "Test Budget1 user".to_string(),
            description: Some("This is a description of Test Budget1 user.".to_string()),
            categories: budget1_categories,
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..400_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let created_budgets = vec![
            dao.create_budget(&new_budget1, created_user.id).unwrap(),
            budget0,
        ];

        let entry0 = InputEntry {
            budget_id: created_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category_id: None,
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
            name: None,
            category_id: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_budgets[1].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..800_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category_id: None,
            note: Some(String::from("This is 2 little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_budgets[1].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(800_000_000..900_000_000)),
            name: None,
            category_id: None,
            note: None,
        };

        let created_entries = vec![
            vec![entry0.clone(), entry1.clone()],
            vec![entry2.clone(), entry3.clone()],
        ];

        dao.create_entry(&entry0, created_user.id).unwrap();
        dao.create_entry(&entry1, created_user.id).unwrap();

        dao.create_entry(&entry2, created_user.id).unwrap();
        dao.create_entry(&entry3, created_user.id).unwrap();

        let mut fetched_budgets = dao.get_all_budgets_for_user(created_user.id).unwrap();
        assert_eq!(fetched_budgets.len(), created_budgets.len());
        assert!(!fetched_budgets.is_empty());

        if fetched_budgets[0].id != created_budgets[0].id {
            fetched_budgets.reverse();
        }

        for i in 0..fetched_budgets.len() {
            assert_eq!(fetched_budgets[i].id, created_budgets[i].id);
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

                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }

            assert!(!fetched_budgets[i].entries.is_empty());
            assert_eq!(fetched_budgets[i].entries.len(), created_entries[i].len());

            for j in 0..fetched_budgets[i].entries.len() {
                let fetched_entry = &fetched_budgets[i].entries[j];
                let created_entry = &created_entries[i][j];

                assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
                assert_eq!(fetched_entry.date, created_entry.date);
                assert_eq!(fetched_entry.name, created_entry.name);
                assert_eq!(fetched_entry.category_id, created_entry.category_id);
                assert_eq!(fetched_entry.note, created_entry.note);
            }
        }
    }

    #[test]
    fn test_get_all_budgets_for_user_between_dates() {
        let db_thread_pool = &*test_env::db::DB_THREAD_POOL;
        let mut dao = Dao::new(db_thread_pool);

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

        let created_user = user::Dao::new(db_thread_pool)
            .create_user(
                &new_user,
                &hash_params,
                vec![32, 4, 23, 53, 75, 23, 43, 10, 11].as_slice(),
            )
            .unwrap();

        let too_early_budget = InputBudget {
            name: format!("Test Too_Early {user_number}"),
            description: Some(format!(
                "This is a description of Test Too_Early {user_number}.",
            )),
            categories: Vec::new(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..100_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(100_000_000..200_000_000)),
        };

        let in_range_budget0 = InputBudget {
            name: format!("Test Budget1 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget1 {user_number}.",
            )),
            categories: Vec::new(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(200_000_000..300_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..700_000_000)),
        };

        let in_range_budget1 = InputBudget {
            name: format!("Test Budget2 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget2 {user_number}.",
            )),
            categories: Vec::new(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(300_000_000..400_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
        };

        let in_range_budget2 = InputBudget {
            name: format!("Test Budget2 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget2 {user_number}.",
            )),
            categories: Vec::new(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(600_000_000..700_000_000)),
        };

        let too_late_budget = InputBudget {
            name: format!("Test Budget3 {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget3 {user_number}.",
            )),
            categories: Vec::new(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..800_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(800_000_000..900_000_000)),
        };

        let mut in_range_budgets = Vec::new();

        dao.create_budget(&too_early_budget, created_user.id)
            .unwrap();

        in_range_budgets.push(
            dao.create_budget(&in_range_budget0, created_user.id)
                .unwrap(),
        );

        in_range_budgets.push(
            dao.create_budget(&in_range_budget1, created_user.id)
                .unwrap(),
        );

        in_range_budgets.push(
            dao.create_budget(&in_range_budget2, created_user.id)
                .unwrap(),
        );

        dao.create_budget(&too_late_budget, created_user.id)
            .unwrap();

        let entry0 = InputEntry {
            budget_id: in_range_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..700_000_000)),
            name: Some(format!("Test Entry 0 for {user_number}")),
            category_id: None,
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: in_range_budgets[0].id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(200_000_000..500_000_000)),
            name: None,
            category_id: None,
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
            entry5.clone(),
            entry4.clone(),
            entry3.clone(),
            entry2.clone(),
            entry1.clone(),
            entry0.clone(),
        ];

        dao.create_entry(&entry0, created_user.id).unwrap();
        dao.create_entry(&entry1, created_user.id).unwrap();

        dao.create_entry(&entry2, created_user.id).unwrap();
        dao.create_entry(&entry3, created_user.id).unwrap();

        dao.create_entry(&entry4, created_user.id).unwrap();
        dao.create_entry(&entry5, created_user.id).unwrap();

        let fetched_budgets = dao
            .get_all_budgets_for_user_between_dates(
                created_user.id,
                SystemTime::UNIX_EPOCH + Duration::from_secs(200_000_000),
                SystemTime::UNIX_EPOCH + Duration::from_secs(700_000_000),
            )
            .unwrap();
        assert_eq!(fetched_budgets.len(), in_range_budgets.len());
        assert!(!fetched_budgets.is_empty());

        for i in 0..fetched_budgets.len() {
            assert_eq!(fetched_budgets[i].id, in_range_budgets[i].id);
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

            assert!(fetched_budgets[i].categories.is_empty());
            assert_eq!(
                fetched_budgets[i].categories.len(),
                in_range_budgets[i].categories.len()
            );

            for (j, fetched_cat) in fetched_budgets[i].categories.iter().enumerate() {
                let in_range_cat = &in_range_budgets[i].categories[j];

                assert_eq!(fetched_cat.budget_id, in_range_cat.budget_id);
                assert_eq!(fetched_cat.id, in_range_cat.id);
                assert_eq!(fetched_cat.name, in_range_cat.name);
                assert_eq!(fetched_cat.limit_cents, in_range_cat.limit_cents);
                assert_eq!(fetched_cat.color, in_range_cat.color);
            }

            for (j, fetched_entry) in fetched_budgets[i].entries.iter().enumerate() {
                let created_entry = &created_entries[j];

                assert_eq!(fetched_entry.amount_cents, created_entry.amount_cents);
                assert_eq!(fetched_entry.date, created_entry.date);
                assert_eq!(fetched_entry.name, created_entry.name);
                assert_eq!(fetched_entry.category_id, created_entry.category_id);
                assert_eq!(fetched_entry.note, created_entry.note);
            }
        }
    }
}
