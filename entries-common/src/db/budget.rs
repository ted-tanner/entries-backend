use diesel::associations::GroupedBy;
use diesel::{
    dsl, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::messages::{
    Budget as BudgetMessage, BudgetList, EntryIdAndCategoryId, InvitationId, UuidV4,
};
use crate::messages::{BudgetFrame, BudgetFrameCategory, Category as CategoryMessage};
use crate::messages::{BudgetIdAndEncryptionKey, CategoryWithTempId};
use crate::messages::{BudgetShareInvite, BudgetShareInviteList, Entry as EntryMessage};
use crate::models::budget::{Budget, NewBudget};
use crate::models::budget_accept_key::{BudgetAcceptKey, NewBudgetAcceptKey};
use crate::models::budget_access_key::{BudgetAccessKey, NewBudgetAccessKey};
use crate::models::budget_share_invite::{BudgetShareInvitePublicData, NewBudgetShareInvite};
use crate::models::category::{Category, NewCategory};
use crate::models::entry::{Entry, NewEntry};
use crate::schema::budget_accept_keys as budget_accept_key_fields;
use crate::schema::budget_accept_keys::dsl::budget_accept_keys;
use crate::schema::budget_access_keys as budget_access_key_fields;
use crate::schema::budget_access_keys::dsl::budget_access_keys;
use crate::schema::budget_share_invites as budget_share_invite_fields;
use crate::schema::budget_share_invites::dsl::budget_share_invites;
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
        &self,
        key_id: Uuid,
        budget_id: Uuid,
    ) -> Result<BudgetAccessKey, DaoError> {
        Ok(budget_access_keys
            .find((key_id, budget_id))
            .get_result::<BudgetAccessKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_multiple_public_budget_keys(
        &self,
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

    pub fn get_budget_accept_public_key(
        &self,
        key_id: Uuid,
        budget_id: Uuid,
    ) -> Result<BudgetAcceptKey, DaoError> {
        Ok(budget_accept_keys
            .find((key_id, budget_id))
            .get_result::<BudgetAcceptKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_budget_invite_sender_public_key(
        &self,
        invitation_id: Uuid,
    ) -> Result<Vec<u8>, DaoError> {
        Ok(budget_share_invites
            .select(budget_share_invite_fields::sender_public_key)
            .find(invitation_id)
            .get_result::<Vec<u8>>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_budget(&self, budget_id: Uuid) -> Result<BudgetMessage, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budget = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let budget = budgets.find(budget_id).get_result::<Budget>(conn)?;
                let loaded_categories = Category::belonging_to(&budget).load::<Category>(conn)?;
                let loaded_entries = Entry::belonging_to(&budget).load::<Entry>(conn)?;

                let category_messages = loaded_categories
                    .into_iter()
                    .map(|c| CategoryMessage {
                        id: c.id.into(),
                        budget_id: c.budget_id.into(),
                        encrypted_blob: c.encrypted_blob,
                        version_nonce: c.version_nonce,
                        modified_timestamp: c.modified_timestamp.try_into().unwrap_or_default(),
                    })
                    .collect();

                let entry_messages = loaded_entries
                    .into_iter()
                    .map(|e| EntryMessage {
                        id: e.id.into(),
                        budget_id: e.budget_id.into(),
                        category_id: e.category_id.as_ref().map(UuidV4::from),
                        encrypted_blob: e.encrypted_blob,
                        version_nonce: e.version_nonce,
                        modified_timestamp: e.modified_timestamp.try_into().unwrap_or_default(),
                    })
                    .collect();

                Ok(BudgetMessage {
                    id: budget.id.into(),
                    encrypted_blob: budget.encrypted_blob,
                    categories: category_messages,
                    entries: entry_messages,
                    version_nonce: budget.version_nonce,
                    modified_timestamp: budget.modified_timestamp.try_into().unwrap_or_default(),
                })
            })?;

        Ok(output_budget)
    }

    pub fn get_multiple_budgets_by_id(&self, budget_ids: &[Uuid]) -> Result<BudgetList, DaoError> {
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
                    let category_messages = budget_categories
                        .into_iter()
                        .map(|c| CategoryMessage {
                            id: c.id.into(),
                            budget_id: c.budget_id.into(),
                            encrypted_blob: c.encrypted_blob,
                            version_nonce: c.version_nonce,
                            modified_timestamp: c.modified_timestamp.try_into().unwrap_or_default(),
                        })
                        .collect();

                    let entry_messages = budget_entries
                        .into_iter()
                        .map(|e| EntryMessage {
                            id: e.id.into(),
                            budget_id: e.budget_id.into(),
                            category_id: e.category_id.as_ref().map(UuidV4::from),
                            encrypted_blob: e.encrypted_blob,
                            version_nonce: e.version_nonce,
                            modified_timestamp: e.modified_timestamp.try_into().unwrap_or_default(),
                        })
                        .collect();

                    let output_budget = BudgetMessage {
                        id: budget.id.into(),
                        encrypted_blob: budget.encrypted_blob,
                        version_nonce: budget.version_nonce,
                        modified_timestamp: budget
                            .modified_timestamp
                            .try_into()
                            .unwrap_or_default(),
                        categories: category_messages,
                        entries: entry_messages,
                    };

                    output_budgets.push(output_budget);
                }

                Ok(output_budgets)
            })?;

        Ok(BudgetList {
            budgets: output_budgets,
        })
    }

    pub fn create_budget(
        &self,
        encrypted_blob: &[u8],
        version_nonce: i64,
        budget_categories: &[CategoryWithTempId],
        user_public_budget_key: &[u8],
    ) -> Result<BudgetFrame, DaoError> {
        let current_time = SystemTime::now();
        let budget_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        let new_budget = NewBudget {
            id: budget_id,
            encrypted_blob,
            version_nonce,
            modified_timestamp: current_time,
        };

        let new_budget_access_key = NewBudgetAccessKey {
            key_id,
            budget_id,
            public_key: user_public_budget_key,
            read_only: false,
        };

        let mut new_categories = Vec::new();
        let mut new_category_temp_ids = Vec::new();

        for category in budget_categories.iter() {
            let new_category = NewCategory {
                budget_id,
                id: Uuid::new_v4(),
                encrypted_blob: &category.encrypted_blob,
                version_nonce: category.version_nonce,
                modified_timestamp: current_time,
            };

            new_categories.push(new_category);
            new_category_temp_ids.push(category.temp_id);
        }

        let mut output_budget = BudgetFrame {
            access_key_id: key_id.into(),
            id: budget_id.into(),
            category_ids: Vec::with_capacity(budget_categories.len()),
            modified_timestamp: current_time.try_into().unwrap_or_default(),
        };

        for i in 0..budget_categories.len() {
            let category_frame = BudgetFrameCategory {
                temp_id: new_category_temp_ids[i],
                real_id: new_categories[i].id.into(),
            };

            output_budget.category_ids.push(category_frame);
        }

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(budgets)
                    .values(&new_budget)
                    .execute(conn)?;

                dsl::insert_into(budget_access_keys)
                    .values(&new_budget_access_key)
                    .execute(conn)?;

                dsl::insert_into(categories)
                    .values(new_categories)
                    .execute(conn)
            })?;

        Ok(output_budget)
    }

    pub fn update_budget(
        &self,
        budget_id: Uuid,
        edited_budget_data: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = dsl::update(
                    budgets
                        .find(budget_id)
                        .filter(budget_fields::version_nonce.eq(expected_previous_version_nonce)),
                )
                .set((
                    budget_fields::modified_timestamp.eq(dsl::now),
                    budget_fields::encrypted_blob.eq(edited_budget_data),
                    budget_fields::version_nonce.eq(version_nonce),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = budgets
                        .select(budget_fields::version_nonce)
                        .find(budget_id)
                        .first::<i64>(conn);

                    match current_version_nonce {
                        Ok(existing_nonce) => {
                            if existing_nonce != expected_previous_version_nonce {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn invite_user(
        &self,
        recipient_user_email: &str,
        sender_public_key: &[u8],
        encryption_key_encrypted: &[u8],
        budget_info_encrypted: &[u8],
        sender_info_encrypted: &[u8],
        share_info_symmetric_key_encrypted: &[u8],
        recipient_public_key_id_used_by_sender: Uuid,
        recipient_public_key_id_used_by_server: Uuid,
        budget_id: Uuid,
        expiration: SystemTime,
        read_only: bool,
        budget_accept_key_id: Uuid,
        budget_accept_key_id_encrypted: &[u8],
        budget_accept_public_key: &[u8],
        budget_accept_private_key_encrypted: &[u8],
        budget_accept_key_info_encrypted: &[u8],
    ) -> Result<InvitationId, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let budget_accept_key = NewBudgetAcceptKey {
            key_id: budget_accept_key_id,
            budget_id,
            public_key: budget_accept_public_key,
            expiration,
            read_only,
        };

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
            budget_accept_private_key_encrypted,
            budget_info_encrypted,
            sender_info_encrypted,
            budget_accept_key_info_encrypted,
            budget_accept_key_id_encrypted,
            share_info_symmetric_key_encrypted,
            recipient_public_key_id_used_by_sender,
            recipient_public_key_id_used_by_server,
            created_unix_timestamp_intdiv_five_million,
        };

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(budget_share_invites)
                    .values(&budget_share_invite)
                    .execute(conn)?;

                dsl::insert_into(budget_accept_keys)
                    .values(&budget_accept_key)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(InvitationId {
            value: budget_share_invite.id.into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_invitation(
        &self,
        accept_key_id: Uuid,
        budget_id: Uuid,
        read_only: bool,
        invitation_id: Uuid,
        recipient_user_email: &str,
        recipient_budget_user_access_public_key: &[u8],
    ) -> Result<BudgetIdAndEncryptionKey, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_budget_key = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let new_budget_access_key = NewBudgetAccessKey {
                    key_id: Uuid::new_v4(),
                    budget_id,
                    public_key: recipient_budget_user_access_public_key,
                    read_only,
                };

                diesel::insert_into(budget_access_keys)
                    .values(&new_budget_access_key)
                    .execute(conn)?;

                let budget_encryption_key_encrypted =
                    diesel::delete(budget_share_invites.find(invitation_id).filter(
                        budget_share_invite_fields::recipient_user_email.eq(recipient_user_email),
                    ))
                    .returning(budget_share_invite_fields::encryption_key_encrypted)
                    .get_result::<Vec<u8>>(conn)?;

                diesel::delete(budget_accept_keys.find((accept_key_id, budget_id)))
                    .execute(conn)?;

                Ok(BudgetIdAndEncryptionKey {
                    budget_id: budget_id.into(),
                    budget_access_key_id: new_budget_access_key.key_id.into(),
                    encryption_key_encrypted: budget_encryption_key_encrypted,
                    read_only,
                })
            })?;

        Ok(output_budget_key)
    }

    // Used when the recipient deletes the invitation
    pub fn reject_invitation(
        &self,
        invitation_id: Uuid,
        accept_key_id: Uuid,
        recipient_user_email: &str,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let affected_row_count =
                    diesel::delete(budget_share_invites.find(invitation_id).filter(
                        budget_share_invite_fields::recipient_user_email.eq(recipient_user_email),
                    ))
                    .execute(conn)?;

                if affected_row_count != 1 {
                    return Err(diesel::result::Error::NotFound);
                }

                diesel::delete(
                    budget_accept_keys.filter(budget_accept_key_fields::key_id.eq(accept_key_id)),
                )
                .execute(conn)
            })?;

        Ok(())
    }

    pub fn delete_invitation(&self, invitation_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(budget_share_invites.find(invitation_id))
            .execute(&mut self.db_thread_pool.get()?)?;
        Ok(())
    }

    pub fn delete_all_expired_invitations(&self) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        // Not using a database transaction here because these can be deleted separately from
        // each other
        diesel::delete(
            budget_accept_keys.filter(budget_accept_key_fields::expiration.lt(SystemTime::now())),
        )
        .execute(&mut db_connection)?;

        let now_minus_five_million_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("now() should be after UNIX_EPOCH")
            .as_secs()
            - 5_000_000;

        let segment_intdiv_five_million = now_minus_five_million_secs / 5_000_000;
        let segment_intdiv_five_million: i16 = segment_intdiv_five_million
            .try_into()
            .expect("Unix epoch time divided by 5 million should fit in an i16");

        diesel::delete(
            budget_share_invites.filter(
                budget_share_invite_fields::created_unix_timestamp_intdiv_five_million
                    .lt(segment_intdiv_five_million),
            ),
        )
        .execute(&mut db_connection)?;

        Ok(())
    }

    pub fn get_all_pending_invitations(
        &self,
        user_email: &str,
    ) -> Result<BudgetShareInviteList, DaoError> {
        let invites = budget_share_invites
            .select((
                budget_share_invite_fields::id,
                budget_share_invite_fields::budget_info_encrypted,
                budget_share_invite_fields::sender_info_encrypted,
                budget_share_invite_fields::share_info_symmetric_key_encrypted,
                budget_share_invite_fields::budget_accept_key_info_encrypted,
                budget_share_invite_fields::budget_accept_private_key_encrypted,
                budget_share_invite_fields::budget_accept_key_id_encrypted,
                budget_share_invite_fields::recipient_public_key_id_used_by_sender,
                budget_share_invite_fields::recipient_public_key_id_used_by_server,
            ))
            .filter(budget_share_invite_fields::recipient_user_email.eq(user_email))
            .load::<BudgetShareInvitePublicData>(&mut self.db_thread_pool.get()?)?;

        let invites = invites
            .into_iter()
            .map(|i| BudgetShareInvite {
                id: i.id.into(),
                budget_accept_key_encrypted: i.budget_accept_key_encrypted,
                budget_accept_key_id_encrypted: i.budget_accept_key_id_encrypted,
                budget_info_encrypted: i.budget_info_encrypted,
                sender_info_encrypted: i.sender_info_encrypted,
                budget_accept_key_info_encrypted: i.budget_accept_key_info_encrypted,
                share_info_symmetric_key_encrypted: i.share_info_symmetric_key_encrypted,
                recipient_public_key_id_used_by_sender: i
                    .recipient_public_key_id_used_by_sender
                    .into(),
                recipient_public_key_id_used_by_server: i
                    .recipient_public_key_id_used_by_server
                    .into(),
            })
            .collect();

        Ok(BudgetShareInviteList { invites })
    }

    pub fn leave_budget(&self, budget_id: Uuid, key_id: Uuid) -> Result<(), DaoError> {
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

    pub fn create_entry(
        &self,
        encrypted_blob: &[u8],
        version_nonce: i64,
        category_id: Option<Uuid>,
        budget_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let entry_id = Uuid::new_v4();

        let new_entry = NewEntry {
            id: entry_id,
            budget_id,
            category_id,
            encrypted_blob,
            version_nonce,
            modified_timestamp: current_time,
        };

        dsl::insert_into(entries)
            .values(&new_entry)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(entry_id)
    }

    pub fn create_entry_and_category(
        &self,
        entry_encrypted_blob: &[u8],
        entry_version_nonce: i64,
        category_encrypted_blob: &[u8],
        category_version_nonce: i64,
        budget_id: Uuid,
    ) -> Result<EntryIdAndCategoryId, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();

        let new_category = NewCategory {
            id: category_id,
            budget_id,
            encrypted_blob: category_encrypted_blob,
            version_nonce: category_version_nonce,
            modified_timestamp: current_time,
        };

        let new_entry = NewEntry {
            id: entry_id,
            budget_id,
            category_id: Some(category_id),
            encrypted_blob: entry_encrypted_blob,
            version_nonce: entry_version_nonce,
            modified_timestamp: current_time,
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(categories)
                    .values(&new_category)
                    .execute(conn)?;

                dsl::insert_into(entries).values(&new_entry).execute(conn)?;

                Ok(())
            })?;

        Ok(EntryIdAndCategoryId {
            entry_id: entry_id.into(),
            category_id: category_id.into(),
        })
    }

    pub fn update_entry(
        &self,
        entry_id: Uuid,
        entry_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
        category_id: Option<Uuid>,
        budget_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = diesel::update(
                    entries
                        .find(entry_id)
                        .filter(entry_fields::budget_id.eq(budget_id))
                        .filter(entry_fields::version_nonce.eq(expected_previous_version_nonce)),
                )
                .set((
                    entry_fields::category_id.eq(category_id),
                    entry_fields::encrypted_blob.eq(entry_encrypted_blob),
                    entry_fields::version_nonce.eq(version_nonce),
                    entry_fields::modified_timestamp.eq(dsl::now),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = entries
                        .select(entry_fields::version_nonce)
                        .find(entry_id)
                        .first::<i64>(conn);

                    match current_version_nonce {
                        Ok(existing_nonce) => {
                            if existing_nonce != expected_previous_version_nonce {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    pub fn delete_entry(&self, entry_id: Uuid, budget_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            entries
                .find(entry_id)
                .filter(entry_fields::budget_id.eq(budget_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn create_category(
        &self,
        encrypted_blob: &[u8],
        version_nonce: i64,
        budget_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::new_v4();

        let new_category = NewCategory {
            id: category_id,
            budget_id,
            encrypted_blob,
            version_nonce,
            modified_timestamp: current_time,
        };

        dsl::insert_into(categories)
            .values(&new_category)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(category_id)
    }

    pub fn update_category(
        &self,
        category_id: Uuid,
        category_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
        budget_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = diesel::update(
                    categories
                        .find(category_id)
                        .filter(category_fields::budget_id.eq(budget_id))
                        .filter(category_fields::version_nonce.eq(expected_previous_version_nonce)),
                )
                .set((
                    category_fields::encrypted_blob.eq(category_encrypted_blob),
                    category_fields::version_nonce.eq(version_nonce),
                    category_fields::modified_timestamp.eq(dsl::now),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = categories
                        .select(category_fields::version_nonce)
                        .find(category_id)
                        .first::<i64>(conn);

                    match current_version_nonce {
                        Ok(existing_nonce) => {
                            if existing_nonce != expected_previous_version_nonce {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    pub fn delete_category(&self, category_id: Uuid, budget_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            categories
                .find(category_id)
                .filter(category_fields::budget_id.eq(budget_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }
}
