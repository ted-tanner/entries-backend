use diesel::associations::GroupedBy;
use diesel::{
    dsl, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::messages::{Category as CategoryMessage, ContainerFrame, ContainerFrameCategory};
use crate::messages::{CategoryWithTempId, ContainerIdAndEncryptionKey};
use crate::messages::{
    Container as ContainerMessage, ContainerList, EntryIdAndCategoryId, InvitationId,
    Uuid as UuidMessage,
};
use crate::messages::{ContainerShareInvite, ContainerShareInviteList, Entry as EntryMessage};
use crate::models::category::{Category, NewCategory};
use crate::models::container::{Container, NewContainer};
use crate::models::container_accept_key::{ContainerAcceptKey, NewContainerAcceptKey};
use crate::models::container_access_key::{ContainerAccessKey, NewContainerAccessKey};
use crate::models::container_share_invite::{
    ContainerShareInvitePublicData, NewContainerShareInvite,
};
use crate::models::entry::{Entry, NewEntry};
use crate::schema::categories as category_fields;
use crate::schema::categories::dsl::categories;
use crate::schema::container_accept_keys as container_accept_key_fields;
use crate::schema::container_accept_keys::dsl::container_accept_keys;
use crate::schema::container_access_keys as container_access_key_fields;
use crate::schema::container_access_keys::dsl::container_access_keys;
use crate::schema::container_share_invites as container_share_invite_fields;
use crate::schema::container_share_invites::dsl::container_share_invites;
use crate::schema::containers as container_fields;
use crate::schema::containers::dsl::containers;
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

    pub fn get_public_container_key(
        &self,
        key_id: Uuid,
        container_id: Uuid,
    ) -> Result<ContainerAccessKey, DaoError> {
        Ok(container_access_keys
            .find((key_id, container_id))
            .get_result::<ContainerAccessKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_multiple_public_container_keys(
        &self,
        key_ids: &[Uuid],
        container_ids: &[Uuid],
    ) -> Result<Vec<ContainerAccessKey>, DaoError> {
        Ok(container_access_keys
            .filter(
                container_access_key_fields::key_id
                    .eq_any(key_ids)
                    .and(container_access_key_fields::container_id.eq_any(container_ids)),
            )
            .get_results::<ContainerAccessKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_container_accept_public_key(
        &self,
        key_id: Uuid,
        container_id: Uuid,
    ) -> Result<ContainerAcceptKey, DaoError> {
        Ok(container_accept_keys
            .find((key_id, container_id))
            .get_result::<ContainerAcceptKey>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_container_invite_sender_public_key(
        &self,
        invitation_id: Uuid,
    ) -> Result<Vec<u8>, DaoError> {
        Ok(container_share_invites
            .select(container_share_invite_fields::sender_public_key)
            .find(invitation_id)
            .get_result::<Vec<u8>>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_container(&self, container_id: Uuid) -> Result<ContainerMessage, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_container = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let container = containers
                    .find(container_id)
                    .get_result::<Container>(conn)?;
                let loaded_categories =
                    Category::belonging_to(&container).load::<Category>(conn)?;
                let loaded_entries = Entry::belonging_to(&container).load::<Entry>(conn)?;

                let category_messages = loaded_categories
                    .into_iter()
                    .map(|c| CategoryMessage {
                        id: c.id.into(),
                        container_id: c.container_id.into(),
                        encrypted_blob: c.encrypted_blob,
                        version_nonce: c.version_nonce,
                        modified_timestamp: c.modified_timestamp.try_into().unwrap_or_default(),
                    })
                    .collect();

                let entry_messages = loaded_entries
                    .into_iter()
                    .map(|e| EntryMessage {
                        id: e.id.into(),
                        container_id: e.container_id.into(),
                        category_id: e.category_id.as_ref().map(UuidMessage::from),
                        encrypted_blob: e.encrypted_blob,
                        version_nonce: e.version_nonce,
                        modified_timestamp: e.modified_timestamp.try_into().unwrap_or_default(),
                    })
                    .collect();

                Ok(ContainerMessage {
                    id: container.id.into(),
                    encrypted_blob: container.encrypted_blob,
                    categories: category_messages,
                    entries: entry_messages,
                    version_nonce: container.version_nonce,
                    modified_timestamp: container.modified_timestamp.try_into().unwrap_or_default(),
                })
            })?;

        Ok(output_container)
    }

    pub fn get_multiple_containers_by_id(
        &self,
        container_ids: &[Uuid],
    ) -> Result<ContainerList, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_containers = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let loaded_containers = containers
                    .filter(container_fields::id.eq_any(container_ids))
                    .get_results::<Container>(conn)?;
                let loaded_categories = Category::belonging_to(&loaded_containers)
                    .load::<Category>(conn)?
                    .grouped_by(&loaded_containers);
                let loaded_entries = Entry::belonging_to(&loaded_containers)
                    .load::<Entry>(conn)?
                    .grouped_by(&loaded_containers);

                let zipped_containers = loaded_containers
                    .into_iter()
                    .zip(loaded_categories.into_iter())
                    .zip(loaded_entries.into_iter());
                let mut output_containers = Vec::new();

                for ((container, container_categories), container_entries) in zipped_containers {
                    let category_messages = container_categories
                        .into_iter()
                        .map(|c| CategoryMessage {
                            id: c.id.into(),
                            container_id: c.container_id.into(),
                            encrypted_blob: c.encrypted_blob,
                            version_nonce: c.version_nonce,
                            modified_timestamp: c.modified_timestamp.try_into().unwrap_or_default(),
                        })
                        .collect();

                    let entry_messages = container_entries
                        .into_iter()
                        .map(|e| EntryMessage {
                            id: e.id.into(),
                            container_id: e.container_id.into(),
                            category_id: e.category_id.as_ref().map(UuidMessage::from),
                            encrypted_blob: e.encrypted_blob,
                            version_nonce: e.version_nonce,
                            modified_timestamp: e.modified_timestamp.try_into().unwrap_or_default(),
                        })
                        .collect();

                    let output_container = ContainerMessage {
                        id: container.id.into(),
                        encrypted_blob: container.encrypted_blob,
                        version_nonce: container.version_nonce,
                        modified_timestamp: container
                            .modified_timestamp
                            .try_into()
                            .unwrap_or_default(),
                        categories: category_messages,
                        entries: entry_messages,
                    };

                    output_containers.push(output_container);
                }

                Ok(output_containers)
            })?;

        Ok(ContainerList {
            containers: output_containers,
        })
    }

    pub fn create_container(
        &self,
        encrypted_blob: &[u8],
        version_nonce: i64,
        container_categories: &[CategoryWithTempId],
        user_public_container_key: &[u8],
    ) -> Result<ContainerFrame, DaoError> {
        let current_time = SystemTime::now();
        let container_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();

        let new_container = NewContainer {
            id: container_id,
            encrypted_blob,
            version_nonce,
            modified_timestamp: current_time,
        };

        let new_container_access_key = NewContainerAccessKey {
            key_id,
            container_id,
            public_key: user_public_container_key,
            read_only: false,
        };

        let mut new_categories = Vec::new();
        let mut new_category_temp_ids = Vec::new();

        for category in container_categories.iter() {
            let new_category = NewCategory {
                container_id,
                id: Uuid::now_v7(),
                encrypted_blob: &category.encrypted_blob,
                version_nonce: category.version_nonce,
                modified_timestamp: current_time,
            };

            new_categories.push(new_category);
            new_category_temp_ids.push(category.temp_id);
        }

        let mut output_container = ContainerFrame {
            access_key_id: key_id.into(),
            id: container_id.into(),
            category_ids: Vec::with_capacity(container_categories.len()),
            modified_timestamp: current_time.try_into().unwrap_or_default(),
        };

        for i in 0..container_categories.len() {
            let category_frame = ContainerFrameCategory {
                temp_id: new_category_temp_ids[i],
                real_id: new_categories[i].id.into(),
            };

            output_container.category_ids.push(category_frame);
        }

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(containers)
                    .values(&new_container)
                    .execute(conn)?;

                dsl::insert_into(container_access_keys)
                    .values(&new_container_access_key)
                    .execute(conn)?;

                dsl::insert_into(categories)
                    .values(new_categories)
                    .execute(conn)
            })?;

        Ok(output_container)
    }

    pub fn update_container(
        &self,
        container_id: Uuid,
        edited_container_data: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count =
                    dsl::update(containers.find(container_id).filter(
                        container_fields::version_nonce.eq(expected_previous_version_nonce),
                    ))
                    .set((
                        container_fields::modified_timestamp.eq(dsl::now),
                        container_fields::encrypted_blob.eq(edited_container_data),
                        container_fields::version_nonce.eq(version_nonce),
                    ))
                    .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = containers
                        .select(container_fields::version_nonce)
                        .find(container_id)
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
        container_info_encrypted: &[u8],
        sender_info_encrypted: &[u8],
        share_info_symmetric_key_encrypted: &[u8],
        recipient_public_key_id_used_by_sender: Uuid,
        recipient_public_key_id_used_by_server: Uuid,
        container_id: Uuid,
        expiration: SystemTime,
        read_only: bool,
        container_accept_key_id: Uuid,
        container_accept_key_id_encrypted: &[u8],
        container_accept_public_key: &[u8],
        container_accept_private_key_encrypted: &[u8],
        container_accept_key_info_encrypted: &[u8],
    ) -> Result<InvitationId, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let container_accept_key = NewContainerAcceptKey {
            key_id: container_accept_key_id,
            container_id,
            public_key: container_accept_public_key,
            expiration,
            read_only,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get time");
        let created_unix_timestamp_intdiv_five_million: i16 = (now.as_secs() / 5_000_000)
            .try_into()
            .expect("Current timestamp divided by 5,000,00 should fit into an i16");

        let container_share_invite = NewContainerShareInvite {
            id: Uuid::now_v7(),
            recipient_user_email,
            sender_public_key,
            encryption_key_encrypted,
            container_accept_private_key_encrypted,
            container_info_encrypted,
            sender_info_encrypted,
            container_accept_key_info_encrypted,
            container_accept_key_id_encrypted,
            share_info_symmetric_key_encrypted,
            recipient_public_key_id_used_by_sender,
            recipient_public_key_id_used_by_server,
            created_unix_timestamp_intdiv_five_million,
        };

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(container_share_invites)
                    .values(&container_share_invite)
                    .execute(conn)?;

                dsl::insert_into(container_accept_keys)
                    .values(&container_accept_key)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(InvitationId {
            value: container_share_invite.id.into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_invitation(
        &self,
        accept_key_id: Uuid,
        container_id: Uuid,
        read_only: bool,
        invitation_id: Uuid,
        recipient_user_email: &str,
        recipient_container_user_access_public_key: &[u8],
    ) -> Result<ContainerIdAndEncryptionKey, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let output_container_key = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let new_container_access_key = NewContainerAccessKey {
                    key_id: Uuid::now_v7(),
                    container_id,
                    public_key: recipient_container_user_access_public_key,
                    read_only,
                };

                diesel::insert_into(container_access_keys)
                    .values(&new_container_access_key)
                    .execute(conn)?;

                let container_encryption_key_encrypted = diesel::delete(
                    container_share_invites.find(invitation_id).filter(
                        container_share_invite_fields::recipient_user_email
                            .eq(recipient_user_email),
                    ),
                )
                .returning(container_share_invite_fields::encryption_key_encrypted)
                .get_result::<Vec<u8>>(conn)?;

                diesel::delete(container_accept_keys.find((accept_key_id, container_id)))
                    .execute(conn)?;

                Ok(ContainerIdAndEncryptionKey {
                    container_id: container_id.into(),
                    container_access_key_id: new_container_access_key.key_id.into(),
                    encryption_key_encrypted: container_encryption_key_encrypted,
                    read_only,
                })
            })?;

        Ok(output_container_key)
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
                let affected_row_count = diesel::delete(
                    container_share_invites.find(invitation_id).filter(
                        container_share_invite_fields::recipient_user_email
                            .eq(recipient_user_email),
                    ),
                )
                .execute(conn)?;

                if affected_row_count != 1 {
                    return Err(diesel::result::Error::NotFound);
                }

                diesel::delete(
                    container_accept_keys
                        .filter(container_accept_key_fields::key_id.eq(accept_key_id)),
                )
                .execute(conn)
            })?;

        Ok(())
    }

    pub fn delete_invitation(&self, invitation_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(container_share_invites.find(invitation_id))
            .execute(&mut self.db_thread_pool.get()?)?;
        Ok(())
    }

    pub fn delete_all_expired_invitations(&self) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        // Not using a database transaction here because these can be deleted separately from
        // each other
        diesel::delete(
            container_accept_keys
                .filter(container_accept_key_fields::expiration.lt(SystemTime::now())),
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
            container_share_invites.filter(
                container_share_invite_fields::created_unix_timestamp_intdiv_five_million
                    .lt(segment_intdiv_five_million),
            ),
        )
        .execute(&mut db_connection)?;

        Ok(())
    }

    pub fn get_all_pending_invitations(
        &self,
        user_email: &str,
    ) -> Result<ContainerShareInviteList, DaoError> {
        let invites = container_share_invites
            .select((
                container_share_invite_fields::id,
                container_share_invite_fields::container_info_encrypted,
                container_share_invite_fields::sender_info_encrypted,
                container_share_invite_fields::share_info_symmetric_key_encrypted,
                container_share_invite_fields::container_accept_key_info_encrypted,
                container_share_invite_fields::container_accept_private_key_encrypted,
                container_share_invite_fields::container_accept_key_id_encrypted,
                container_share_invite_fields::recipient_public_key_id_used_by_sender,
                container_share_invite_fields::recipient_public_key_id_used_by_server,
            ))
            .filter(container_share_invite_fields::recipient_user_email.eq(user_email))
            .load::<ContainerShareInvitePublicData>(&mut self.db_thread_pool.get()?)?;

        let invites = invites
            .into_iter()
            .map(|i| ContainerShareInvite {
                id: i.id.into(),
                container_accept_key_encrypted: i.container_accept_key_encrypted,
                container_accept_key_id_encrypted: i.container_accept_key_id_encrypted,
                container_info_encrypted: i.container_info_encrypted,
                sender_info_encrypted: i.sender_info_encrypted,
                container_accept_key_info_encrypted: i.container_accept_key_info_encrypted,
                share_info_symmetric_key_encrypted: i.share_info_symmetric_key_encrypted,
                recipient_public_key_id_used_by_sender: i
                    .recipient_public_key_id_used_by_sender
                    .into(),
                recipient_public_key_id_used_by_server: i
                    .recipient_public_key_id_used_by_server
                    .into(),
            })
            .collect();

        Ok(ContainerShareInviteList { invites })
    }

    pub fn leave_container(&self, container_id: Uuid, key_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                diesel::delete(container_access_keys.find((key_id, container_id))).execute(conn)?;

                let users_remaining_in_container = container_access_keys
                    .filter(container_access_key_fields::container_id.eq(container_id))
                    .count()
                    .get_result::<i64>(conn)?;

                if users_remaining_in_container == 0 {
                    diesel::delete(containers.find(container_id)).execute(conn)?;
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
        container_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let entry_id = Uuid::now_v7();

        let new_entry = NewEntry {
            id: entry_id,
            container_id,
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
        container_id: Uuid,
    ) -> Result<EntryIdAndCategoryId, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::now_v7();
        let entry_id = Uuid::now_v7();

        let new_category = NewCategory {
            id: category_id,
            container_id,
            encrypted_blob: category_encrypted_blob,
            version_nonce: category_version_nonce,
            modified_timestamp: current_time,
        };

        let new_entry = NewEntry {
            id: entry_id,
            container_id,
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
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = diesel::update(
                    entries
                        .find(entry_id)
                        .filter(entry_fields::container_id.eq(container_id))
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

    pub fn delete_entry(&self, entry_id: Uuid, container_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            entries
                .find(entry_id)
                .filter(entry_fields::container_id.eq(container_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn create_category(
        &self,
        encrypted_blob: &[u8],
        version_nonce: i64,
        container_id: Uuid,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let category_id = Uuid::now_v7();

        let new_category = NewCategory {
            id: category_id,
            container_id,
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
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = diesel::update(
                    categories
                        .find(category_id)
                        .filter(category_fields::container_id.eq(container_id))
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

    pub fn delete_category(&self, category_id: Uuid, container_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(
            categories
                .find(category_id)
                .filter(category_fields::container_id.eq(container_id)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }
}
