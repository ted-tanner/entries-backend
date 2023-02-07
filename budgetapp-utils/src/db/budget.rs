use diesel::associations::GroupedBy;
use diesel::sql_types::{self, Timestamp, VarChar};
use diesel::{
    dsl, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, JoinOnDsl,
    NullableExpressionMethods, QueryDsl, RunQueryDsl,
};
use std::time::SystemTime;
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::budget::{Budget, NewBudget};
use crate::models::budget_share_invite::NewBudgetShareInvite;
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::models::tombstone::NewTombstone;
use crate::models::user_budget::NewUserBudget;
use crate::request_io::{
    InputBudget, InputCategory, InputEntry, InputEntryAndCategory, OutputBudget, OutputBudgetFrame,
    OutputBudgetFrameCategory, OutputBudgetIdAndEncryptionKey, OutputBudgetShareInviteWithoutKey,
    OutputEntryIdAndCategoryId,
};
use crate::schema::budget_share_invites as budget_share_invite_fields;
use crate::schema::budget_share_invites::dsl::budget_share_invites;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::entries as entry_fields;
use crate::schema::entries::dsl::entries;

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
        budget_data: InputBudget,
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

    pub fn update_budget_key(
        &mut self,
        budget_id: Uuid,
        encrypted_key: &str,
        is_encrypted_with_aes: bool,
        user_id: Uuid,
    ) -> Result<(), DaoError> {
        dsl::update(user_budgets.find((user_id, budget_id)))
            .set((
                user_budget_fields::encryption_key_encrypted.eq(encrypted_key),
                user_budget_fields::encryption_key_is_encrypted_with_aes_not_rsa
                    .eq(is_encrypted_with_aes),
            ))
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
                    .find((sender_user_id, budget_id))
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
        entry_data: InputEntry,
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
        entry_and_category_data: InputEntryAndCategory,
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
        category_data: InputCategory,
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
