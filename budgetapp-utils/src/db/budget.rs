use diesel::associations::GroupedBy;
use diesel::{
    dsl, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::budget::{Budget, NewBudget};
use crate::models::budget_access_key::{BudgetAccessKey, NewBudgetAccessKey};
use crate::models::budget_share_invite::NewBudgetShareInvite;
use crate::models::budget_share_key::{BudgetShareKey, NewBudgetShareKey};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::request_io::{
    InputBudget, InputEntryAndCategory, OutputBudget, OutputBudgetFrame, OutputBudgetFrameCategory,
    OutputBudgetIdAndEncryptionKey, OutputBudgetShareInviteWithoutKey, OutputEntryIdAndCategoryId,
    OutputShareIdAndKeyId,
};
use crate::schema::budget_access_keys as budget_access_key_fields;
use crate::schema::budget_access_keys::dsl::budget_access_keys;
use crate::schema::budget_share_invites as budget_share_invite_fields;
use crate::schema::budget_share_invites::dsl::budget_share_invites;
use crate::schema::budget_share_keys as budget_share_key_fields;
use crate::schema::budget_share_keys::dsl::budget_share_keys;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::entries as entry_fields;
use crate::schema::entries::dsl::entries;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn get_public_budget_key(
        &mut self,
        key_id: Uuid,
        budget_id: Uuid,
    ) -> Result<BudgetAccessKey, DaoError> {
        Ok(budget_access_keys
            .find((key_id, budget_id))
            .get_result::<BudgetAccessKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_multiple_public_budget_keys(
        &mut self,
        key_ids: &[Uuid],
        budget_ids: &[Uuid],
    ) -> Result<Vec<BudgetAccessKey>, DaoError> {
        Ok(budget_access_keys
            .filter(
                budget_access_key_fields::key_id
                    .eq_any(key_ids)
                    .and(budget_access_key_fields::budget_id.eq_any(budget_ids)),
            )
            .get_results::<BudgetAccessKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_budget_share_invite_public_key(
        &mut self,
        key_id: Uuid,
        budget_id: Uuid,
    ) -> Result<BudgetShareKey, DaoError> {
        Ok(budget_share_keys
            .find((key_id, budget_id))
            .get_result::<BudgetShareKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_budget(&mut self, budget_id: Uuid) -> Result<OutputBudget, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budget = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let budget = budgets.find(budget_id).get_result::<Budget>(conn)?;
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
        budget_ids: &[Uuid],
    ) -> Result<Vec<OutputBudget>, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budgets = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let loaded_budgets = budgets
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

    pub fn create_budget(
        &mut self,
        budget_data: InputBudget,
    ) -> Result<OutputBudgetFrame, DaoError> {
        let current_time = SystemTime::now();
        let budget_id = Uuid::new_v4();

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&budget_data.encrypted_blob);

        let new_budget = NewBudget {
            id: budget_id,
            encrypted_blob: &budget_data.encrypted_blob,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        let new_budget_access_key = NewBudgetAccessKey {
            key_id: Uuid::new_v4(),
            budget_id,
            public_key: &budget_data.user_public_budget_key,
            read_only: false,
        };

        let mut category_hashes = Vec::new();

        for category in &budget_data.categories {
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(&category.encrypted_blob);

            category_hashes.push(sha1_hasher.finalize());
        }

        let mut budget_categories = Vec::new();
        let mut budget_category_temp_ids = Vec::new();

        for (i, category) in budget_data.categories.iter().enumerate() {
            let new_category = NewCategory {
                budget_id,
                id: Uuid::new_v4(),
                encrypted_blob: &category.encrypted_blob,
                encrypted_blob_sha1_hash: &category_hashes[i],
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
                dsl::insert_into(budget_access_keys)
                    .values(&new_budget_access_key)
                    .execute(conn)?;

                dsl::insert_into(budgets)
                    .values(&new_budget)
                    .execute(conn)?;

                dsl::insert_into(categories)
                    .values(budget_categories)
                    .execute(conn)
            })?;

        Ok(output_budget)
    }

    pub fn update_budget(
        &mut self,
        budget_id: Uuid,
        edited_budget_data: &[u8],
        expected_previous_data_hash: &[u8],
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                let previous_hash = budgets
                    .select(budget_fields::encrypted_blob_sha1_hash)
                    .find(budget_id)
                    .get_result::<Vec<u8>>(conn)?;

                if previous_hash != expected_previous_data_hash {
                    return Err(DaoError::OutOfDateHash);
                }

                let mut sha1_hasher = Sha1::new();
                sha1_hasher.update(edited_budget_data);

                dsl::update(budgets.find(budget_id))
                    .set((
                        budget_fields::modified_timestamp.eq(SystemTime::now()),
                        budget_fields::encrypted_blob.eq(edited_budget_data),
                        budget_fields::encrypted_blob_sha1_hash
                            .eq(sha1_hasher.finalize().as_slice()),
                    ))
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn invite_user(
        &mut self,
        recipient_user_email: &str,
        sender_public_key: &[u8],
        encryption_key_encrypted: &[u8],
        budget_share_private_key_encrypted: &[u8],
        budget_info_encrypted: &[u8],
        sender_info_encrypted: &[u8],
        budget_share_private_key_info_encrypted: &[u8],
        share_info_symmetric_key_encrypted: &[u8],
        budget_id: Uuid,
        budget_share_public_key: &[u8],
        expiration: SystemTime,
        read_only: bool,
    ) -> Result<OutputShareIdAndKeyId, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get time");
        let created_unix_timestamp_intdiv_five_million: i16 = (now.as_secs() / 5_000_000)
            .try_into()
            .expect("Current timestamp divided by 5,000,00 should fit into an i16");

        let budget_share_invite = NewBudgetShareInvite {
            id: Uuid::new_v4(),
            recipient_user_email,
            sender_public_key,
            encryption_key_encrypted,
            budget_share_private_key_encrypted,
            budget_info_encrypted,
            sender_info_encrypted,
            budget_share_private_key_info_encrypted,
            share_info_symmetric_key_encrypted,
            created_unix_timestamp_intdiv_five_million,
        };

        let budget_share_key = NewBudgetShareKey {
            key_id: Uuid::new_v4(),
            budget_id,
            public_key: budget_share_public_key,
            expiration,
            read_only,
        };

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(budget_share_invites)
                    .values(&budget_share_invite)
                    .execute(conn)?;

                dsl::insert_into(budget_share_keys)
                    .values(&budget_share_key)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(OutputShareIdAndKeyId {
            share_id: budget_share_invite.id,
            share_key_id: budget_share_key.key_id,
        })
    }

    pub fn accept_invitation(
        &mut self,
        share_id: Uuid,
        recipient_user_email: &str,
        share_key: BudgetShareKey,
        recipient_budget_user_public_key: &[u8],
    ) -> Result<OutputBudgetIdAndEncryptionKey, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budget_key = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let new_budget_access_key = NewBudgetAccessKey {
                    key_id: Uuid::new_v4(),
                    budget_id: share_key.budget_id,
                    public_key: recipient_budget_user_public_key,
                    read_only: share_key.read_only,
                };

                diesel::insert_into(budget_access_keys)
                    .values(&new_budget_access_key)
                    .execute(conn)?;

                let budget_encryption_key_encrypted =
                    diesel::delete(budget_share_invites.find(share_id).filter(
                        budget_share_invite_fields::recipient_user_email.eq(recipient_user_email),
                    ))
                    .returning(budget_share_invite_fields::encryption_key_encrypted)
                    .get_result::<Vec<u8>>(conn)?;

                diesel::delete(budget_share_keys.find((share_key.key_id, share_key.budget_id)))
                    .execute(conn)?;

                Ok(OutputBudgetIdAndEncryptionKey {
                    budget_id: share_key.budget_id,
                    budget_access_key_id: new_budget_access_key.key_id,
                    encryption_key_encrypted: budget_encryption_key_encrypted,
                    read_only: share_key.read_only,
                })
            })?;

        Ok(output_budget_key)
    }

    // Used when the recipient deletes the invitation
    pub fn reject_invitation(
        &mut self,
        share_id: Uuid,
        share_key_id: Uuid,
        recipient_user_email: &str,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let affected_row_count =
                    diesel::delete(budget_share_invites.find(share_id).filter(
                        budget_share_invite_fields::recipient_user_email.eq(recipient_user_email),
                    ))
                    .execute(conn)?;

                if affected_row_count != 1 {
                    return Err(diesel::result::Error::NotFound);
                }

                diesel::delete(
                    budget_share_keys.filter(budget_share_key_fields::key_id.eq(share_key_id)),
                )
                .execute(conn)
            })?;

        Ok(())
    }

    // Used when the sender deletes the invitation, not the recipient
    pub fn delete_invitation(
        &mut self,
        share_id: Uuid,
        share_key_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let affected_row_count =
                    diesel::delete(budget_share_invites.find(share_id)).execute(conn)?;

                if affected_row_count != 1 {
                    return Err(diesel::result::Error::NotFound);
                }

                diesel::delete(
                    budget_share_keys.filter(budget_share_key_fields::key_id.eq(share_key_id)),
                )
                .execute(conn)
            })?;

        Ok(())
    }

    pub fn get_all_pending_invitations_for_user(
        &mut self,
        user_email: &str,
    ) -> Result<Vec<OutputBudgetShareInviteWithoutKey>, DaoError> {
        Ok(budget_share_invites
            .select((
                budget_share_invite_fields::budget_share_private_key_encrypted,
                budget_share_invite_fields::budget_info_encrypted,
                budget_share_invite_fields::sender_info_encrypted,
                budget_share_invite_fields::budget_share_private_key_info_encrypted,
                budget_share_invite_fields::share_info_symmetric_key_encrypted,
            ))
            .filter(budget_share_invite_fields::recipient_user_email.eq(user_email))
            .load::<OutputBudgetShareInviteWithoutKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn leave_budget(&mut self, budget_id: Uuid, key_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                diesel::delete(budget_access_keys.find((key_id, budget_id))).execute(conn)?;

                let users_remaining_in_budget = budget_access_keys
                    .filter(budget_access_key_fields::budget_id.eq(budget_id))
                    .count()
                    .get_result::<i64>(conn)?;

                if users_remaining_in_budget == 0 {
                    diesel::delete(budgets.find(budget_id)).execute(conn)?;
                }

                Ok(())
            })?;

        Ok(())
    }

    // TODO: Check read_only in the handler after getting the public key
    pub fn create_entry(
        &mut self,
        encrypted_blob: &[u8],
        budget_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let entry_id = Uuid::new_v4();

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(encrypted_blob);

        let new_entry = NewEntry {
            id: entry_id,
            budget_id,
            encrypted_blob,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        dsl::insert_into(entries)
            .values(&new_entry)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(entry_id)
    }

    pub fn create_entry_and_category(
        &mut self,
        entry_and_category_data: InputEntryAndCategory,
        budget_id: Uuid,
    ) -> Result<OutputEntryIdAndCategoryId, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&entry_and_category_data.entry_encrypted_blob);

        let new_entry = NewEntry {
            id: entry_id,
            budget_id,
            encrypted_blob: &entry_and_category_data.entry_encrypted_blob,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&entry_and_category_data.category_encrypted_blob);

        let new_category = NewCategory {
            id: category_id,
            budget_id,
            encrypted_blob: &entry_and_category_data.category_encrypted_blob,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(entries).values(&new_entry).execute(conn)?;

                dsl::insert_into(categories)
                    .values(&new_category)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(OutputEntryIdAndCategoryId {
            entry_id,
            category_id,
        })
    }

    pub fn update_entry(
        &mut self,
        entry_id: Uuid,
        entry_encrypted_blob: &[u8],
        expected_previous_data_hash: &[u8],
        budget_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                let previous_hash = entries
                    .find(entry_id)
                    .select(entry_fields::encrypted_blob_sha1_hash)
                    .get_result::<Vec<u8>>(conn)?;

                if previous_hash != expected_previous_data_hash {
                    return Err(DaoError::OutOfDateHash);
                }

                let mut sha1_hasher = Sha1::new();
                sha1_hasher.update(entry_encrypted_blob);

                diesel::update(
                    entries
                        .find(entry_id)
                        .filter(entry_fields::budget_id.eq(budget_id)),
                )
                .set((
                    entry_fields::encrypted_blob.eq(entry_encrypted_blob),
                    entry_fields::encrypted_blob_sha1_hash.eq(sha1_hasher.finalize().as_slice()),
                    entry_fields::modified_timestamp.eq(SystemTime::now()),
                ))
                .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn delete_entry(&mut self, entry_id: Uuid, budget_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            entries
                .find(entry_id)
                .filter(entry_fields::budget_id.eq(budget_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn create_category(
        &mut self,
        encrypted_blob: &[u8],
        budget_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(encrypted_blob);

        let new_category = NewCategory {
            id: category_id,
            budget_id,
            encrypted_blob,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        dsl::insert_into(categories)
            .values(&new_category)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(category_id)
    }

    pub fn update_category(
        &mut self,
        category_id: Uuid,
        category_encrypted_blob: &[u8],
        expected_previous_data_hash: &[u8],
        budget_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                let previous_hash = categories
                    .find(category_id)
                    .select(category_fields::encrypted_blob_sha1_hash)
                    .get_result::<Vec<u8>>(conn)?;

                if previous_hash != expected_previous_data_hash {
                    return Err(DaoError::OutOfDateHash);
                }

                let mut sha1_hasher = Sha1::new();
                sha1_hasher.update(category_encrypted_blob);

                diesel::update(
                    categories
                        .find(category_id)
                        .filter(category_fields::budget_id.eq(budget_id)),
                )
                .set((
                    category_fields::encrypted_blob.eq(category_encrypted_blob),
                    category_fields::encrypted_blob_sha1_hash.eq(sha1_hasher.finalize().as_slice()),
                    category_fields::modified_timestamp.eq(SystemTime::now()),
                ))
                .execute(conn)?;

                Ok(())
            })
    }

    pub fn delete_category(&mut self, category_id: Uuid, budget_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            categories
                .find(category_id)
                .filter(category_fields::budget_id.eq(budget_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }
}
