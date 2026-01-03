use diesel::associations::GroupedBy;
use diesel::{dsl, BelongingToDsl, BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbAsyncPool};
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
    db_async_pool: DbAsyncPool,
}

impl Dao {
    pub fn new(db_async_pool: &DbAsyncPool) -> Self {
        Self {
            db_async_pool: db_async_pool.clone(),
        }
    }

    pub async fn get_public_container_key(
        &self,
        key_id: Uuid,
        container_id: Uuid,
    ) -> Result<ContainerAccessKey, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(container_access_keys
            .find((key_id, container_id))
            .get_result::<ContainerAccessKey>(&mut conn)
            .await?)
    }

    pub async fn get_multiple_public_container_keys(
        &self,
        key_ids: &[Uuid],
        container_ids: &[Uuid],
    ) -> Result<Vec<ContainerAccessKey>, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(container_access_keys
            .filter(
                container_access_key_fields::key_id
                    .eq_any(key_ids)
                    .and(container_access_key_fields::container_id.eq_any(container_ids)),
            )
            .get_results::<ContainerAccessKey>(&mut conn)
            .await?)
    }

    pub async fn get_container_accept_public_key(
        &self,
        key_id: Uuid,
        container_id: Uuid,
    ) -> Result<ContainerAcceptKey, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(container_accept_keys
            .find((key_id, container_id))
            .get_result::<ContainerAcceptKey>(&mut conn)
            .await?)
    }

    pub async fn get_container_invite_sender_public_key(
        &self,
        invitation_id: Uuid,
    ) -> Result<Vec<u8>, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(container_share_invites
            .select(container_share_invite_fields::sender_public_key)
            .find(invitation_id)
            .get_result::<Vec<u8>>(&mut conn)
            .await?)
    }

    pub async fn get_container(&self, container_id: Uuid) -> Result<ContainerMessage, DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        let output_container = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let container = containers
                        .find(container_id)
                        .get_result::<Container>(conn)
                        .await?;

                    let (loaded_categories, loaded_entries) = if container.deleted_at.is_some() {
                        (Vec::new(), Vec::new())
                    } else {
                        (
                            Category::belonging_to(&container)
                                .load::<Category>(conn)
                                .await?,
                            Entry::belonging_to(&container).load::<Entry>(conn).await?,
                        )
                    };

                    let category_messages = loaded_categories
                        .into_iter()
                        .map(|c| CategoryMessage {
                            id: c.id.into(),
                            container_id: c.container_id.into(),
                            encrypted_blob: c.encrypted_blob,
                            version_nonce: c.version_nonce,
                            modified_timestamp: c.modified_timestamp.try_into().unwrap_or_default(),
                            deleted_at: c.deleted_at.and_then(|t| t.try_into().ok()),
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
                            deleted_at: e.deleted_at.and_then(|t| t.try_into().ok()),
                        })
                        .collect();

                    Ok(ContainerMessage {
                        id: container.id.into(),
                        encrypted_blob: container.encrypted_blob,
                        categories: category_messages,
                        entries: entry_messages,
                        version_nonce: container.version_nonce,
                        modified_timestamp: container
                            .modified_timestamp
                            .try_into()
                            .unwrap_or_default(),
                        deleted_at: container.deleted_at.and_then(|t| t.try_into().ok()),
                    })
                })
            })
            .await?;

        Ok(output_container)
    }

    pub async fn get_multiple_containers_by_id(
        &self,
        container_ids: &[Uuid],
    ) -> Result<ContainerList, DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        let output_containers = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let loaded_containers = containers
                        .filter(container_fields::id.eq_any(container_ids))
                        .get_results::<Container>(conn)
                        .await?;

                    let live_containers: Vec<&Container> = loaded_containers
                        .iter()
                        .filter(|c| c.deleted_at.is_none())
                        .collect();

                    let live_categories = Category::belonging_to(&live_containers)
                        .load::<Category>(conn)
                        .await?
                        .grouped_by(&live_containers);

                    let live_entries = Entry::belonging_to(&live_containers)
                        .load::<Entry>(conn)
                        .await?
                        .grouped_by(&live_containers);

                    let mut live_categories_iter = live_categories.into_iter();
                    let mut live_entries_iter = live_entries.into_iter();

                    let mut output_containers = Vec::new();

                    for container in loaded_containers {
                        // If this container is soft-deleted, give it no categories/entries
                        let (container_categories, container_entries) =
                            if container.deleted_at.is_some() {
                                (Vec::new(), Vec::new())
                            } else {
                                (
                                    live_categories_iter.next().unwrap_or_default(),
                                    live_entries_iter.next().unwrap_or_default(),
                                )
                            };

                        let category_messages = container_categories
                            .into_iter()
                            .map(|c| CategoryMessage {
                                id: c.id.into(),
                                container_id: c.container_id.into(),
                                encrypted_blob: c.encrypted_blob,
                                version_nonce: c.version_nonce,
                                modified_timestamp: c
                                    .modified_timestamp
                                    .try_into()
                                    .unwrap_or_default(),
                                deleted_at: c.deleted_at.and_then(|t| t.try_into().ok()),
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
                                modified_timestamp: e
                                    .modified_timestamp
                                    .try_into()
                                    .unwrap_or_default(),
                                deleted_at: e.deleted_at.and_then(|t| t.try_into().ok()),
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
                            deleted_at: container.deleted_at.and_then(|t| t.try_into().ok()),
                        };

                        output_containers.push(output_container);
                    }

                    Ok(output_containers)
                })
            })
            .await?;

        Ok(ContainerList {
            containers: output_containers,
        })
    }

    pub async fn create_container(
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

        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    dsl::insert_into(containers)
                        .values(&new_container)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(container_access_keys)
                        .values(&new_container_access_key)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(categories)
                        .values(new_categories)
                        .execute(conn)
                        .await
                })
            })
            .await?;

        Ok(output_container)
    }

    pub async fn update_container(
        &self,
        container_id: Uuid,
        edited_container_data: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = dsl::update(containers.find(container_id).filter(
                        container_fields::version_nonce.eq(expected_previous_version_nonce),
                    ))
                    .set((
                        container_fields::modified_timestamp.eq(dsl::now),
                        container_fields::encrypted_blob.eq(edited_container_data),
                        container_fields::version_nonce.eq(version_nonce),
                        container_fields::deleted_at.eq(None::<SystemTime>),
                    ))
                    .execute(conn)
                    .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the version_nonce was out-of-date
                        let current_version_nonce = containers
                            .select(container_fields::version_nonce)
                            .find(container_id)
                            .first::<i64>(conn)
                            .await;

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
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn invite_user(
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
        let mut db_connection = self.db_async_pool.get().await?;

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

        let invitation_id = Uuid::now_v7();
        let container_share_invite = NewContainerShareInvite {
            id: invitation_id,
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
                Box::pin(async move {
                    dsl::insert_into(container_share_invites)
                        .values(&container_share_invite)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(container_accept_keys)
                        .values(&container_accept_key)
                        .execute(conn)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(InvitationId {
            value: invitation_id.into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn accept_invitation(
        &self,
        accept_key_id: Uuid,
        container_id: Uuid,
        read_only: bool,
        invitation_id: Uuid,
        recipient_user_email: &str,
        recipient_container_user_access_public_key: &[u8],
    ) -> Result<ContainerIdAndEncryptionKey, DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        let output_container_key = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let new_container_access_key = NewContainerAccessKey {
                        key_id: Uuid::now_v7(),
                        container_id,
                        public_key: recipient_container_user_access_public_key,
                        read_only,
                    };

                    diesel::insert_into(container_access_keys)
                        .values(&new_container_access_key)
                        .execute(conn)
                        .await?;

                    let container_encryption_key_encrypted = diesel::delete(
                        container_share_invites.find(invitation_id).filter(
                            container_share_invite_fields::recipient_user_email
                                .eq(recipient_user_email),
                        ),
                    )
                    .returning(container_share_invite_fields::encryption_key_encrypted)
                    .get_result::<Vec<u8>>(conn)
                    .await?;

                    diesel::delete(container_accept_keys.find((accept_key_id, container_id)))
                        .execute(conn)
                        .await?;

                    Ok(ContainerIdAndEncryptionKey {
                        container_id: container_id.into(),
                        container_access_key_id: new_container_access_key.key_id.into(),
                        encryption_key_encrypted: container_encryption_key_encrypted,
                        read_only,
                    })
                })
            })
            .await?;

        Ok(output_container_key)
    }

    // Used when the recipient deletes the invitation
    pub async fn reject_invitation(
        &self,
        invitation_id: Uuid,
        accept_key_id: Uuid,
        recipient_user_email: &str,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = diesel::delete(
                        container_share_invites.find(invitation_id).filter(
                            container_share_invite_fields::recipient_user_email
                                .eq(recipient_user_email),
                        ),
                    )
                    .execute(conn)
                    .await?;

                    if affected_row_count != 1 {
                        return Err(diesel::result::Error::NotFound);
                    }

                    diesel::delete(
                        container_accept_keys
                            .filter(container_accept_key_fields::key_id.eq(accept_key_id)),
                    )
                    .execute(conn)
                    .await
                })
            })
            .await?;

        Ok(())
    }

    pub async fn delete_invitation(&self, invitation_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(container_share_invites.find(invitation_id))
            .execute(&mut self.db_async_pool.get().await?)
            .await?;
        Ok(())
    }

    pub async fn delete_all_expired_invitations(&self) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        // Not using a database transaction here because these can be deleted separately from
        // each other
        diesel::delete(
            container_accept_keys
                .filter(container_accept_key_fields::expiration.lt(SystemTime::now())),
        )
        .execute(&mut db_connection)
        .await?;

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
        .execute(&mut db_connection)
        .await?;

        Ok(())
    }

    pub async fn get_all_pending_invitations(
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
            .load::<ContainerShareInvitePublicData>(&mut self.db_async_pool.get().await?)
            .await?;

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

    pub async fn leave_container(&self, container_id: Uuid, key_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    diesel::delete(container_access_keys.find((key_id, container_id)))
                        .execute(conn)
                        .await?;

                    let users_remaining_in_container = container_access_keys
                        .filter(container_access_key_fields::container_id.eq(container_id))
                        .count()
                        .get_result::<i64>(conn)
                        .await?;

                    if users_remaining_in_container == 0 {
                        // Hard delete. The only user in the container is leaving. They will no longer
                        // have access, so there is no need to keep the container around.
                        diesel::delete(containers.find(container_id))
                            .execute(conn)
                            .await?;
                    }

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }

    pub async fn create_entry(
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
            .execute(&mut self.db_async_pool.get().await?)
            .await?;

        Ok(entry_id)
    }

    pub async fn create_entry_and_category(
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

        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    dsl::insert_into(categories)
                        .values(&new_category)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(entries)
                        .values(&new_entry)
                        .execute(conn)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(EntryIdAndCategoryId {
            entry_id: entry_id.into(),
            category_id: category_id.into(),
        })
    }

    pub async fn update_entry(
        &self,
        entry_id: Uuid,
        entry_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
        category_id: Option<Uuid>,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = diesel::update(
                        entries
                            .find(entry_id)
                            .filter(entry_fields::container_id.eq(container_id))
                            .filter(
                                entry_fields::version_nonce.eq(expected_previous_version_nonce),
                            ),
                    )
                    .set((
                        entry_fields::category_id.eq(category_id),
                        entry_fields::encrypted_blob.eq(entry_encrypted_blob),
                        entry_fields::version_nonce.eq(version_nonce),
                        entry_fields::modified_timestamp.eq(dsl::now),
                        entry_fields::deleted_at.eq(None::<SystemTime>),
                    ))
                    .execute(conn)
                    .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the version_nonce was out-of-date
                        let current_version_nonce = entries
                            .select(entry_fields::version_nonce)
                            .find(entry_id)
                            .first::<i64>(conn)
                            .await;

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
            })
            .await
    }

    pub async fn soft_delete_entry(
        &self,
        entry_id: Uuid,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::update(
            entries
                .find(entry_id)
                .filter(entry_fields::container_id.eq(container_id))
                .filter(entry_fields::deleted_at.is_null()),
        )
        .set((
            entry_fields::deleted_at.eq(dsl::now),
            entry_fields::encrypted_blob.eq(&[] as &[u8]),
        ))
        .execute(&mut self.db_async_pool.get().await?)
        .await?;

        Ok(())
    }

    pub async fn hard_delete_entry(
        &self,
        entry_id: Uuid,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::delete(
            entries
                .find(entry_id)
                .filter(entry_fields::container_id.eq(container_id)),
        )
        .execute(&mut self.db_async_pool.get().await?)
        .await?;

        Ok(())
    }

    pub async fn create_category(
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
            .execute(&mut self.db_async_pool.get().await?)
            .await?;

        Ok(category_id)
    }

    pub async fn update_category(
        &self,
        category_id: Uuid,
        category_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = diesel::update(
                        categories
                            .find(category_id)
                            .filter(category_fields::container_id.eq(container_id))
                            .filter(
                                category_fields::version_nonce.eq(expected_previous_version_nonce),
                            ),
                    )
                    .set((
                        category_fields::encrypted_blob.eq(category_encrypted_blob),
                        category_fields::version_nonce.eq(version_nonce),
                        category_fields::modified_timestamp.eq(dsl::now),
                        category_fields::deleted_at.eq(None::<SystemTime>),
                    ))
                    .execute(conn)
                    .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the version_nonce was out-of-date
                        let current_version_nonce = categories
                            .select(category_fields::version_nonce)
                            .find(category_id)
                            .first::<i64>(conn)
                            .await;

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
            })
            .await
    }

    pub async fn soft_delete_category(
        &self,
        category_id: Uuid,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    // Soft delete the category and clear its blob
                    diesel::update(
                        categories
                            .find(category_id)
                            .filter(category_fields::container_id.eq(container_id))
                            .filter(category_fields::deleted_at.is_null()),
                    )
                    .set((
                        category_fields::deleted_at.eq(dsl::now),
                        category_fields::encrypted_blob.eq(&[] as &[u8]),
                    ))
                    .execute(conn)
                    .await?;

                    // Set category_id to None for all entries that reference this category
                    diesel::update(
                        entries
                            .filter(entry_fields::container_id.eq(container_id))
                            .filter(entry_fields::category_id.eq(category_id)),
                    )
                    .set(entry_fields::category_id.eq(None::<Uuid>))
                    .execute(conn)
                    .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }

    pub async fn hard_delete_category(
        &self,
        category_id: Uuid,
        container_id: Uuid,
    ) -> Result<(), DaoError> {
        diesel::delete(
            categories
                .find(category_id)
                .filter(category_fields::container_id.eq(container_id)),
        )
        .execute(&mut self.db_async_pool.get().await?)
        .await?;

        Ok(())
    }

    pub async fn soft_delete_container(&self, container_id: Uuid) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    // Soft delete the container and clear its blob
                    diesel::update(
                        containers
                            .find(container_id)
                            .filter(container_fields::deleted_at.is_null()),
                    )
                    .set((
                        container_fields::deleted_at.eq(dsl::now),
                        container_fields::encrypted_blob.eq(&[] as &[u8]),
                    ))
                    .execute(conn)
                    .await?;

                    // Soft delete all entries in the container and clear their blobs
                    diesel::update(
                        entries
                            .filter(entry_fields::container_id.eq(container_id))
                            .filter(entry_fields::deleted_at.is_null()),
                    )
                    .set((
                        entry_fields::deleted_at.eq(dsl::now),
                        entry_fields::encrypted_blob.eq(&[] as &[u8]),
                    ))
                    .execute(conn)
                    .await?;

                    // Soft delete all categories in the container and clear their blobs
                    diesel::update(
                        categories
                            .filter(category_fields::container_id.eq(container_id))
                            .filter(category_fields::deleted_at.is_null()),
                    )
                    .set((
                        category_fields::deleted_at.eq(dsl::now),
                        category_fields::encrypted_blob.eq(&[] as &[u8]),
                    ))
                    .execute(conn)
                    .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }

    pub async fn hard_delete_container(&self, container_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(containers.find(container_id))
            .execute(&mut self.db_async_pool.get().await?)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{self, TestUserData};
    use crate::db::user;
    use crate::db::DbAsyncConnection;
    use crate::messages::{CategoryWithTempId, EntryIdAndCategoryId};
    use crate::models::category::{Category as CategoryModel, NewCategory};
    use crate::models::container_share_invite::NewContainerShareInvite;
    use crate::models::entry::{Entry as EntryModel, NewEntry};
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
    use diesel::{dsl, ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use std::time::{Duration, SystemTime};

    fn dao() -> Dao {
        Dao::new(test_utils::db_async_pool())
    }

    async fn insert_container_with_key() -> (Uuid, Uuid) {
        let mut conn = test_utils::db_async_conn().await;
        let container_id = test_utils::insert_container(&mut conn).await;
        let key_id = Uuid::now_v7();
        test_utils::insert_container_access_key(&mut conn, container_id, key_id).await;
        (container_id, key_id)
    }

    async fn cleanup_container(container_id: Uuid) {
        let mut conn = test_utils::db_async_conn().await;
        let _ = diesel::delete(containers.find(container_id))
            .execute(&mut conn)
            .await;
    }

    async fn insert_category_record(conn: &mut DbAsyncConnection, container_id: Uuid) -> Uuid {
        use diesel_async::RunQueryDsl;
        let category_id = Uuid::now_v7();
        let new_category = NewCategory {
            id: category_id,
            container_id,
            encrypted_blob: &test_utils::random_bytes(16),
            version_nonce: 1,
            modified_timestamp: SystemTime::now(),
        };
        dsl::insert_into(categories)
            .values(&new_category)
            .execute(conn)
            .await
            .unwrap();
        category_id
    }

    async fn insert_entry_record(
        conn: &mut DbAsyncConnection,
        container_id: Uuid,
        category_id: Option<Uuid>,
    ) -> Uuid {
        use diesel_async::RunQueryDsl;
        let entry_id = Uuid::now_v7();
        let new_entry = NewEntry {
            id: entry_id,
            container_id,
            category_id,
            encrypted_blob: &test_utils::random_bytes(16),
            version_nonce: 1,
            modified_timestamp: SystemTime::now(),
        };
        dsl::insert_into(entries)
            .values(&new_entry)
            .execute(conn)
            .await
            .unwrap();
        entry_id
    }

    async fn insert_accept_key_record(
        conn: &mut DbAsyncConnection,
        container_id: Uuid,
        key_id: Uuid,
        expiration: SystemTime,
        read_only: bool,
    ) {
        use diesel_async::RunQueryDsl;
        let key = NewContainerAcceptKey {
            key_id,
            container_id,
            public_key: &test_utils::random_bytes(32),
            expiration,
            read_only,
        };
        dsl::insert_into(container_accept_keys)
            .values(&key)
            .execute(conn)
            .await
            .unwrap();
    }

    async fn insert_share_invite_record(
        conn: &mut DbAsyncConnection,
        recipient_email: &str,
        accept_key_id: Uuid,
    ) -> (Uuid, Vec<u8>) {
        use diesel_async::RunQueryDsl;
        let accept_key_encrypted = accept_key_id.as_bytes().to_vec();
        let invite = NewContainerShareInvite {
            id: Uuid::now_v7(),
            recipient_user_email: recipient_email,
            sender_public_key: &test_utils::random_bytes(32),
            encryption_key_encrypted: &test_utils::random_bytes(32),
            container_accept_private_key_encrypted: &test_utils::random_bytes(32),
            container_info_encrypted: &test_utils::random_bytes(32),
            sender_info_encrypted: &test_utils::random_bytes(32),
            container_accept_key_info_encrypted: &test_utils::random_bytes(32),
            container_accept_key_id_encrypted: &accept_key_encrypted,
            share_info_symmetric_key_encrypted: &test_utils::random_bytes(32),
            recipient_public_key_id_used_by_sender: Uuid::now_v7(),
            recipient_public_key_id_used_by_server: Uuid::now_v7(),
            created_unix_timestamp_intdiv_five_million: 0,
        };
        dsl::insert_into(container_share_invites)
            .values(&invite)
            .execute(conn)
            .await
            .unwrap();

        (invite.id, invite.sender_public_key.to_vec())
    }

    async fn create_verified_user() -> (Uuid, TestUserData) {
        let user_dao = user::Dao::new(test_utils::db_async_pool());
        let inserted = test_utils::create_user_with_dao(&user_dao).await;
        let mut conn = test_utils::db_async_conn().await;
        dsl::update(crate::schema::users::dsl::users.find(inserted.id))
            .set(crate::schema::users::dsl::is_verified.eq(true))
            .execute(&mut conn)
            .await
            .unwrap();
        (inserted.id, inserted.data)
    }

    #[tokio::test]
    async fn container_key_queries_work() {
        let dao = dao();
        let (container_id, key_id) = insert_container_with_key().await;

        let key = dao
            .get_public_container_key(key_id, container_id)
            .await
            .unwrap();
        assert_eq!(key.key_id, key_id);

        let extra_key_id = Uuid::now_v7();
        {
            let mut conn = test_utils::db_async_conn().await;
            test_utils::insert_container_access_key(&mut conn, container_id, extra_key_id).await;
        }

        let keys = dao
            .get_multiple_public_container_keys(&[extra_key_id], &[container_id])
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, extra_key_id);

        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn container_accept_and_invite_key_queries_work() {
        let dao = dao();
        let (container_id, _key_id) = insert_container_with_key().await;
        let accept_key_id = Uuid::now_v7();
        let (user_id, user_data) = create_verified_user().await;

        {
            let mut conn = test_utils::db_async_conn().await;
            insert_accept_key_record(
                &mut conn,
                container_id,
                accept_key_id,
                SystemTime::now(),
                false,
            )
            .await;
            insert_share_invite_record(&mut conn, &user_data.email, accept_key_id).await;
        }

        let accept_key = dao
            .get_container_accept_public_key(accept_key_id, container_id)
            .await
            .unwrap();
        assert_eq!(accept_key.key_id, accept_key_id);

        let invite_id = diesel_async::RunQueryDsl::first::<Uuid>(
            container_share_invites.select(container_share_invite_fields::id),
            &mut test_utils::db_async_conn().await,
        )
        .await
        .unwrap();
        let sender_key = dao
            .get_container_invite_sender_public_key(invite_id)
            .await
            .unwrap();
        assert!(!sender_key.is_empty());

        dao.delete_invitation(invite_id).await.unwrap();
        test_utils::delete_user(user_id).await;
        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn container_retrieval_includes_categories_and_entries() {
        let dao = dao();
        let mut conn = test_utils::db_async_conn().await;
        let live_container = test_utils::insert_container(&mut conn).await;
        let live_category = insert_category_record(&mut conn, live_container).await;
        insert_entry_record(&mut conn, live_container, Some(live_category)).await;

        let deleted_container = test_utils::insert_container(&mut conn).await;
        insert_category_record(&mut conn, deleted_container).await;
        insert_entry_record(&mut conn, deleted_container, None).await;
        dsl::update(containers.find(deleted_container))
            .set(container_fields::deleted_at.eq(Some(SystemTime::now())))
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);

        let container = dao.get_container(live_container).await.unwrap();
        assert_eq!(
            Uuid::try_from(container.id).unwrap(),
            live_container,
            "container id mismatch"
        );
        assert_eq!(container.categories.len(), 1);
        assert_eq!(container.entries.len(), 1);

        let mut listed = dao
            .get_multiple_containers_by_id(&[live_container, deleted_container])
            .await
            .unwrap()
            .containers;
        listed.sort_by_key(|c| Uuid::try_from(c.id.clone()).unwrap());

        let live_result = &listed[0];
        assert_eq!(live_result.categories.len(), 1);
        assert_eq!(live_result.entries.len(), 1);

        let deleted_result = &listed[1];
        assert!(deleted_result.categories.is_empty());
        assert!(deleted_result.entries.is_empty());

        cleanup_container(live_container).await;
        cleanup_container(deleted_container).await;
    }

    #[tokio::test]
    async fn create_and_update_container_flow() {
        let dao = dao();
        let encrypted_blob = test_utils::random_bytes(32);
        let categories_input = vec![
            CategoryWithTempId {
                temp_id: 10,
                encrypted_blob: test_utils::random_bytes(16),
                version_nonce: 1,
            },
            CategoryWithTempId {
                temp_id: 11,
                encrypted_blob: test_utils::random_bytes(16),
                version_nonce: 2,
            },
        ];
        let user_key = test_utils::random_bytes(32);

        let frame = dao
            .create_container(&encrypted_blob, 5, &categories_input, &user_key)
            .await
            .unwrap();
        let container_id = Uuid::try_from(frame.id).unwrap();

        let mut conn = test_utils::db_async_conn().await;
        let created_container = containers
            .find(container_id)
            .first::<Container>(&mut conn)
            .await
            .unwrap();
        assert_eq!(created_container.encrypted_blob, encrypted_blob);
        assert_eq!(frame.category_ids.len(), 2);

        let new_blob = test_utils::random_bytes(24);
        dao.update_container(container_id, &new_blob, 6, 5)
            .await
            .unwrap();
        let updated_container = containers
            .find(container_id)
            .first::<Container>(&mut conn)
            .await
            .unwrap();
        assert_eq!(updated_container.encrypted_blob, new_blob);
        assert_eq!(updated_container.version_nonce, 6);

        let err = dao
            .update_container(container_id, &new_blob, 7, 4)
            .await
            .unwrap_err();
        assert!(matches!(err, DaoError::OutOfDate));

        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn invite_and_accept_invitation_flow() {
        let dao = dao();
        let (container_id, _) = insert_container_with_key().await;
        let (user_id, user_data) = create_verified_user().await;
        let accept_key_id = Uuid::now_v7();
        let sender_public_key = test_utils::random_bytes(32);
        let encryption_key_encrypted = test_utils::random_bytes(48);
        let container_info = test_utils::random_bytes(32);
        let sender_info = test_utils::random_bytes(24);
        let share_info = test_utils::random_bytes(20);
        let accept_public_key = test_utils::random_bytes(32);
        let accept_private_key = test_utils::random_bytes(32);
        let accept_info = test_utils::random_bytes(32);
        let accept_key_id_encrypted = test_utils::random_bytes(32);

        let invite = dao
            .invite_user(
                &user_data.email,
                &sender_public_key,
                &encryption_key_encrypted,
                &container_info,
                &sender_info,
                &share_info,
                Uuid::now_v7(),
                Uuid::now_v7(),
                container_id,
                SystemTime::now() + Duration::from_secs(60),
                false,
                accept_key_id,
                &accept_key_id_encrypted,
                &accept_public_key,
                &accept_private_key,
                &accept_info,
            )
            .await
            .unwrap();

        let pending = dao
            .get_all_pending_invitations(&user_data.email)
            .await
            .unwrap();
        assert_eq!(pending.invites.len(), 1);

        let recipient_access_public_key = test_utils::random_bytes(32);
        let container_token = dao
            .accept_invitation(
                accept_key_id,
                container_id,
                false,
                Uuid::try_from(invite.value).unwrap(),
                &user_data.email,
                &recipient_access_public_key,
            )
            .await
            .unwrap();
        assert_eq!(
            Uuid::try_from(container_token.container_id).unwrap(),
            container_id
        );

        let mut conn = test_utils::db_async_conn().await;
        assert_eq!(
            container_share_invites
                .filter(container_share_invite_fields::recipient_user_email.eq(&user_data.email))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );
        assert!(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container_id))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap()
                >= 1
        );
        assert_eq!(
            container_accept_keys
                .filter(container_accept_key_fields::key_id.eq(accept_key_id))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );

        test_utils::delete_user(user_id).await;
        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn reject_invitation_removes_rows() {
        let dao = dao();
        let (container_id, _) = insert_container_with_key().await;
        let (user_id, user_data) = create_verified_user().await;
        let accept_key_id = Uuid::now_v7();

        let invite = dao
            .invite_user(
                &user_data.email,
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                Uuid::now_v7(),
                Uuid::now_v7(),
                container_id,
                SystemTime::now() + Duration::from_secs(60),
                true,
                accept_key_id,
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
            )
            .await
            .unwrap();

        dao.reject_invitation(
            Uuid::try_from(invite.value).unwrap(),
            accept_key_id,
            &user_data.email,
        )
        .await
        .unwrap();

        let mut conn = test_utils::db_async_conn().await;
        assert_eq!(
            container_share_invites
                .filter(container_share_invite_fields::recipient_user_email.eq(&user_data.email))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            container_accept_keys
                .filter(container_accept_key_fields::key_id.eq(accept_key_id))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );

        test_utils::delete_user(user_id).await;
        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn invitation_cleanup_handles_manual_and_expired_records() {
        let dao = dao();
        let (container_id, _) = insert_container_with_key().await;
        let (user_id, user_data) = create_verified_user().await;

        let invite = dao
            .invite_user(
                &user_data.email,
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                Uuid::now_v7(),
                Uuid::now_v7(),
                container_id,
                SystemTime::now() + Duration::from_secs(60),
                false,
                Uuid::now_v7(),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
                &test_utils::random_bytes(16),
            )
            .await
            .unwrap();

        let invite_id = Uuid::try_from(invite.value).unwrap();
        dao.delete_invitation(invite_id).await.unwrap();

        {
            let mut conn = test_utils::db_async_conn().await;
            assert_eq!(
                container_share_invites
                    .filter(container_share_invite_fields::id.eq(invite_id))
                    .count()
                    .get_result::<i64>(&mut conn)
                    .await
                    .unwrap(),
                0
            );
        }

        // Create expired rows
        let expired_accept_key = Uuid::now_v7();
        let live_accept_key = Uuid::now_v7();
        let expired_invite_id = Uuid::now_v7();
        let live_invite_id = Uuid::now_v7();
        {
            let mut conn = test_utils::db_async_conn().await;
            insert_accept_key_record(
                &mut conn,
                container_id,
                expired_accept_key,
                SystemTime::now() - Duration::from_secs(60),
                false,
            )
            .await;
            insert_accept_key_record(
                &mut conn,
                container_id,
                live_accept_key,
                SystemTime::now() + Duration::from_secs(3600),
                false,
            )
            .await;

            let sender_public_key = test_utils::random_bytes(16);
            let encryption_key = test_utils::random_bytes(16);
            let accept_private_key = test_utils::random_bytes(16);
            let container_info = test_utils::random_bytes(16);
            let sender_info = test_utils::random_bytes(16);
            let accept_info = test_utils::random_bytes(16);
            let accept_key_id_encrypted = test_utils::random_bytes(16);
            let share_info = test_utils::random_bytes(16);
            let recipient_key_id_sender = Uuid::now_v7();
            let recipient_key_id_server = Uuid::now_v7();

            let expired_invite = NewContainerShareInvite {
                id: expired_invite_id,
                recipient_user_email: &user_data.email,
                sender_public_key: &sender_public_key,
                encryption_key_encrypted: &encryption_key,
                container_accept_private_key_encrypted: &accept_private_key,
                container_info_encrypted: &container_info,
                sender_info_encrypted: &sender_info,
                container_accept_key_info_encrypted: &accept_info,
                container_accept_key_id_encrypted: &accept_key_id_encrypted,
                share_info_symmetric_key_encrypted: &share_info,
                recipient_public_key_id_used_by_sender: recipient_key_id_sender,
                recipient_public_key_id_used_by_server: recipient_key_id_server,
                created_unix_timestamp_intdiv_five_million: 0,
            };
            let live_invite = NewContainerShareInvite {
                id: live_invite_id,
                recipient_user_email: &user_data.email,
                sender_public_key: &sender_public_key,
                encryption_key_encrypted: &encryption_key,
                container_accept_private_key_encrypted: &accept_private_key,
                container_info_encrypted: &container_info,
                sender_info_encrypted: &sender_info,
                container_accept_key_info_encrypted: &accept_info,
                container_accept_key_id_encrypted: &accept_key_id_encrypted,
                share_info_symmetric_key_encrypted: &share_info,
                recipient_public_key_id_used_by_sender: recipient_key_id_sender,
                recipient_public_key_id_used_by_server: recipient_key_id_server,
                created_unix_timestamp_intdiv_five_million: i16::MAX,
            };

            dsl::insert_into(container_share_invites)
                .values(&expired_invite)
                .execute(&mut conn)
                .await
                .unwrap();
            dsl::insert_into(container_share_invites)
                .values(&live_invite)
                .execute(&mut conn)
                .await
                .unwrap();
        }

        dao.delete_all_expired_invitations().await.unwrap();

        let mut conn = test_utils::db_async_conn().await;
        let remaining_accept_keys = container_accept_keys
            .filter(container_accept_key_fields::key_id.eq(live_accept_key))
            .count()
            .get_result::<i64>(&mut conn)
            .await
            .unwrap();
        assert_eq!(remaining_accept_keys, 1);
        assert_eq!(
            container_accept_keys
                .filter(container_accept_key_fields::key_id.eq(expired_accept_key))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            container_share_invites
                .filter(container_share_invite_fields::id.eq(expired_invite_id))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            container_share_invites
                .filter(container_share_invite_fields::id.eq(live_invite_id))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap(),
            1
        );

        diesel::delete(container_share_invites.find(live_invite_id))
            .execute(&mut conn)
            .await
            .unwrap();

        test_utils::delete_user(user_id).await;
        cleanup_container(container_id).await;
    }

    #[tokio::test]
    async fn leave_container_handles_remaining_users() {
        let dao = dao();
        let (container_with_two, key_one) = insert_container_with_key().await;
        let key_two = Uuid::now_v7();
        {
            let mut conn = test_utils::db_async_conn().await;
            test_utils::insert_container_access_key(&mut conn, container_with_two, key_two).await;
        }

        dao.leave_container(container_with_two, key_one)
            .await
            .unwrap();
        {
            let mut conn = test_utils::db_async_conn().await;
            let remaining = container_access_keys
                .filter(container_access_key_fields::container_id.eq(container_with_two))
                .count()
                .get_result::<i64>(&mut conn)
                .await
                .unwrap();
            assert_eq!(remaining, 1);
        }

        let (solo_container, solo_key) = insert_container_with_key().await;
        dao.leave_container(solo_container, solo_key).await.unwrap();
        {
            let mut conn = test_utils::db_async_conn().await;
            assert!(diesel_async::RunQueryDsl::first::<Container>(
                containers.find(solo_container),
                &mut conn
            )
            .await
            .is_err());
        }

        cleanup_container(container_with_two).await;
    }

    #[tokio::test]
    async fn entry_crud_flow_covers_all_paths() {
        let dao = dao();
        let (container_id, key_id) = insert_container_with_key().await;
        let EntryIdAndCategoryId {
            entry_id,
            category_id,
        } = dao
            .create_entry_and_category(
                &test_utils::random_bytes(16),
                1,
                &test_utils::random_bytes(16),
                1,
                container_id,
            )
            .await
            .unwrap();
        let entry_uuid = Uuid::try_from(entry_id.clone()).unwrap();
        let category_uuid = Uuid::try_from(category_id.clone()).unwrap();

        dao.update_entry(
            entry_uuid,
            &test_utils::random_bytes(16),
            2,
            1,
            Some(category_uuid),
            container_id,
        )
        .await
        .unwrap();

        let err = dao
            .update_entry(
                Uuid::try_from(entry_id.clone()).unwrap(),
                &test_utils::random_bytes(8),
                3,
                0,
                None,
                container_id,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DaoError::OutOfDate));

        let standalone_entry = dao
            .create_entry(&test_utils::random_bytes(10), 1, None, container_id)
            .await
            .unwrap();

        dao.soft_delete_entry(standalone_entry, container_id)
            .await
            .unwrap();
        dao.hard_delete_entry(standalone_entry, container_id)
            .await
            .unwrap();

        dao.leave_container(container_id, key_id).await.unwrap();
    }

    #[tokio::test]
    async fn category_crud_flow_updates_and_deletes_records() {
        let dao = dao();
        let (container_id, key_id) = insert_container_with_key().await;

        let category_id = dao
            .create_category(&test_utils::random_bytes(10), 1, container_id)
            .await
            .unwrap();
        dao.update_category(
            category_id,
            &test_utils::random_bytes(12),
            2,
            1,
            container_id,
        )
        .await
        .unwrap();

        let err = dao
            .update_category(
                category_id,
                &test_utils::random_bytes(8),
                3,
                1,
                container_id,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DaoError::OutOfDate));

        let entry_id = dao
            .create_entry(
                &test_utils::random_bytes(8),
                1,
                Some(category_id),
                container_id,
            )
            .await
            .unwrap();

        dao.soft_delete_category(category_id, container_id)
            .await
            .unwrap();
        dao.hard_delete_category(category_id, container_id)
            .await
            .unwrap();

        dao.hard_delete_entry(entry_id, container_id).await.unwrap();
        dao.leave_container(container_id, key_id).await.unwrap();
    }

    #[tokio::test]
    async fn soft_and_hard_delete_container_flow() {
        let dao = dao();
        let mut conn = test_utils::db_async_conn().await;
        let container_id = test_utils::insert_container(&mut conn).await;
        let category_id = insert_category_record(&mut conn, container_id).await;
        insert_entry_record(&mut conn, container_id, Some(category_id)).await;
        drop(conn);

        dao.soft_delete_container(container_id).await.unwrap();
        {
            let mut conn = test_utils::db_async_conn().await;
            let container = containers
                .find(container_id)
                .first::<Container>(&mut conn)
                .await
                .unwrap();
            assert!(container.deleted_at.is_some());
            assert!(container.encrypted_blob.is_empty());

            let category = categories
                .find(category_id)
                .first::<CategoryModel>(&mut conn)
                .await
                .unwrap();
            assert!(category.deleted_at.is_some());
            assert!(category.encrypted_blob.is_empty());

            let entry = entries
                .filter(entry_fields::container_id.eq(container_id))
                .first::<EntryModel>(&mut conn)
                .await
                .unwrap();
            assert!(entry.deleted_at.is_some());
            assert!(entry.encrypted_blob.is_empty());
        }

        dao.hard_delete_container(container_id).await.unwrap();
        let mut conn = test_utils::db_async_conn().await;
        assert!(diesel_async::RunQueryDsl::first::<Container>(
            containers.find(container_id),
            &mut conn
        )
        .await
        .is_err());
    }
}
