use entries_common::messages::{
    AcceptKeyInfo, CategoryId, CategoryUpdate, ContainerAccessTokenList, ContainerList,
    EncryptedBlobAndCategoryId, EncryptedBlobUpdate, EntryAndCategory, EntryId, EntryUpdate,
    NewContainer, NewEncryptedBlob, PublicKey, UserInvitationToContainer,
};
use entries_common::models::container_access_key::ContainerAccessKey;
use entries_common::threadrand::SecureRng;
use entries_common::token::container_accept_token::ContainerAcceptToken;
use entries_common::token::container_access_token::ContainerAccessToken;
use entries_common::token::container_invite_sender_token::ContainerInviteSenderToken;
use entries_common::token::Token;
use entries_common::validators::{self, Validity};
use entries_common::{db, db::DaoError, db::DbAsyncPool};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{web, HttpResponse};
use ed25519_dalek as ed25519;
use openssl::rsa::{Padding, Rsa};
use prost::Message;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::env;
use crate::handlers::error::{DoesNotExistType, HttpErrorResponse};
use crate::middleware::auth::{Access, VerifiedToken};
use crate::middleware::special_access_token::SpecialAccessToken;
use crate::middleware::{FromHeader, TokenLocation};

pub async fn get(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_tokens: ProtoBuf<ContainerAccessTokenList>,
) -> Result<HttpResponse, HttpErrorResponse> {
    const INVALID_ID_MSG: &str = "One of the provided container access tokens had an invalid ID";

    if container_access_tokens.tokens.len() > env::CONF.max_container_fetch_count {
        return Err(HttpErrorResponse::TooManyRequested(Cow::Owned(format!(
            "Cannot fetch more than {} containers at once",
            env::CONF.max_container_fetch_count,
        ))));
    }

    let mut tokens = HashMap::with_capacity(container_access_tokens.tokens.len());
    let mut key_ids = Vec::with_capacity(container_access_tokens.tokens.len());
    let mut container_ids = Vec::with_capacity(container_access_tokens.tokens.len());

    for token in container_access_tokens.tokens.iter() {
        let token = ContainerAccessToken::decode(token)
            .map_err(|_| HttpErrorResponse::IncorrectlyFormed(Cow::Borrowed(INVALID_ID_MSG)))?;

        key_ids.push(token.claims.key_id);
        container_ids.push(token.claims.container_id);
        tokens.insert(token.claims.key_id, token);
    }

    let container_dao = db::container::Dao::new(&db_async_pool);
    let public_keys = if container_ids.len() == 1 && key_ids.len() == 1 {
        match container_dao
            .get_public_container_key(key_ids[0], container_ids[0])
            .await
        {
            Ok(key) => vec![key],
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        Cow::Borrowed(INVALID_ID_MSG),
                        DoesNotExistType::Container,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                        "Failed to get container data",
                    )));
                }
            },
        }
    } else {
        match container_dao
            .get_multiple_public_container_keys(&key_ids, &container_ids)
            .await
        {
            Ok(keys) => keys,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        Cow::Borrowed(INVALID_ID_MSG),
                        DoesNotExistType::Container,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                        "Failed to get container data",
                    )));
                }
            },
        }
    };

    if public_keys.len() != tokens.len() {
        return Err(HttpErrorResponse::DoesNotExist(
            Cow::Borrowed(INVALID_ID_MSG),
            DoesNotExistType::Container,
        ));
    }

    for key in public_keys {
        let token = match tokens.get(&key.key_id) {
            Some(t) => t,
            None => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed(INVALID_ID_MSG),
                    DoesNotExistType::Container,
                ))
            }
        };

        token.verify(&key.public_key)?;
    }

    let containers = if container_ids.len() == 1 {
        match container_dao.get_container(container_ids[0]).await {
            Ok(container) => ContainerList {
                containers: vec![container],
            },
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        Cow::Borrowed("One of the provided IDs did not match a container"),
                        DoesNotExistType::Container,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                        "Failed to get container data",
                    )));
                }
            },
        }
    } else {
        match container_dao
            .get_multiple_containers_by_id(&container_ids)
            .await
        {
            Ok(containers) => containers,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        Cow::Borrowed("One of the provided IDs did not match a container"),
                        DoesNotExistType::Container,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                        "Failed to get container data",
                    )));
                }
            },
        }
    };

    Ok(HttpResponse::Ok().protobuf(containers)?)
}

pub async fn create(
    db_async_pool: web::Data<DbAsyncPool>,
    container_data: ProtoBuf<NewContainer>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if container_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Container encrypted blob too large",
        )));
    }

    if container_data.user_public_container_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "User public key too large",
        )));
    }

    for category in container_data.categories.iter() {
        if category.encrypted_blob.len() > env::CONF.max_small_object_size {
            return Err(HttpErrorResponse::InputTooLarge(Cow::Owned(format!(
                "Category encrypted blob too large for category with temp ID {}",
                category.temp_id,
            ))));
        }
    }

    // temp_id is an ID the client generates that allows the server to differentiate between
    // categories when multiple are sent to the server simultaneously. The server doesn't have any
    // other way of differentiating them because they are encrypted.
    let mut temp_id_set = HashSet::with_capacity(container_data.categories.len());
    for category in &container_data.categories {
        temp_id_set.insert(category.temp_id);
    }

    if temp_id_set.len() != container_data.categories.len() {
        return Err(HttpErrorResponse::InvalidState(Cow::Borrowed(
            "Multiple categories with the same ID",
        )));
    }

    let container_dao = db::container::Dao::new(&db_async_pool);
    let new_container = match container_dao
        .create_container(
            &container_data.encrypted_blob,
            container_data.version_nonce,
            &container_data.categories,
            &container_data.user_public_container_key,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                "Failed to create container",
            )));
        }
    };

    Ok(HttpResponse::Created().protobuf(new_container)?)
}

pub async fn edit(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    container_data: ProtoBuf<EncryptedBlobUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if container_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Container encrypted blob too large",
        )));
    }

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao
        .update_container(
            container_access_token.0.claims.container_id,
            &container_data.encrypted_blob,
            container_data.version_nonce,
            container_data.expected_previous_version_nonce,
        )
        .await
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(Cow::Borrowed(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container with ID matching token"),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to edit container",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

#[derive(Debug)]
pub struct AcceptKey {
    key_id: Uuid,
    key_id_encrypted: Vec<u8>,
    public_key: Vec<u8>,
    private_key_encrypted: Vec<u8>,
    key_info_encrypted: Vec<u8>,
}

pub async fn invite_user(
    db_async_pool: web::Data<DbAsyncPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    invitation_info: ProtoBuf<UserInvitationToContainer>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if invitation_info.sender_public_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Sender public key too large",
        )));
    }

    if invitation_info.encryption_key_encrypted.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted encryption key too large",
        )));
    }

    if invitation_info.container_info_encrypted.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Container info encrypted too large",
        )));
    }

    if invitation_info.sender_info_encrypted.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Sender info encrypted too large",
        )));
    }

    if invitation_info.share_info_symmetric_key_encrypted.len() > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted symmetric key too large",
        )));
    }

    if let Validity::Invalid(msg) =
        validators::validate_email_address(&invitation_info.recipient_user_email)
    {
        return Err(HttpErrorResponse::IncorrectlyFormed(Cow::Borrowed(msg)));
    }

    if invitation_info.recipient_user_email == user_access_token.0.user_email {
        return Err(HttpErrorResponse::InvalidState(Cow::Borrowed(
            "Inviter and recipient are the same",
        )));
    }

    let read_only = invitation_info.read_only;
    let expiration: SystemTime = (&invitation_info.expiration).into();

    let invitation_info = Arc::new(invitation_info.0);

    let user_dao = db::user::Dao::new(&db_async_pool);
    let (recipient_pub_key_id, recipient_public_key) = match user_dao
        .get_user_public_key(&invitation_info.recipient_user_email)
        .await
    {
        Ok(k) => (Uuid::try_from(k.id)?, k.value),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No user with given email"),
                    DoesNotExistType::User,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to get recipient user's public key",
                )));
            }
        },
    };

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let accept_key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let accept_public_key = accept_key_pair.verifying_key().to_bytes();
        let accept_private_key = accept_key_pair.as_bytes();

        let recipient_public_key = match Rsa::public_key_from_der(&recipient_public_key) {
            Ok(k) => k,
            Err(_) => {
                sender
                    .send(Err(HttpErrorResponse::IncorrectlyFormed(Cow::Borrowed(
                        "Recipient user's public key is incorrectly formatted",
                    ))))
                    .expect("Sending to channel failed");

                return;
            }
        };

        let mut private_key_encrypted = vec![0; recipient_public_key.size() as usize];
        let encrypted_size = match recipient_public_key.public_encrypt(
            &accept_private_key[..],
            &mut private_key_encrypted,
            Padding::PKCS1,
        ) {
            Ok(s) => s,
            Err(_) => {
                sender
                    .send(Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                        "Failed to encrypt accept key pair using recipient's public key",
                    ))))
                    .expect("Sending to channel failed");

                return;
            }
        };
        private_key_encrypted.truncate(encrypted_size);

        let key_id = Uuid::now_v7();

        let mut key_id_encrypted = vec![0; recipient_public_key.size() as usize];
        let encrypted_size = recipient_public_key
            .public_encrypt(key_id.as_bytes(), &mut key_id_encrypted, Padding::PKCS1)
            .expect("Failed to encrypt using recipient's public key");
        key_id_encrypted.truncate(encrypted_size);

        let key_info = AcceptKeyInfo {
            read_only,
            expiration: expiration
                .duration_since(UNIX_EPOCH)
                .expect("Failed to convert expiration to Unix Epoch time")
                .as_secs(),
        };

        let key_info = key_info.encode_to_vec();

        let mut key_info_encrypted = vec![0; recipient_public_key.size() as usize];
        let encrypted_size = recipient_public_key
            .public_encrypt(&key_info, &mut key_info_encrypted, Padding::PKCS1)
            .expect("Failed to encrypt using recipient's public key");
        key_info_encrypted.truncate(encrypted_size);

        sender
            .send(Ok(AcceptKey {
                key_id,
                key_id_encrypted,
                public_key: accept_public_key.to_vec(),
                private_key_encrypted,
                key_info_encrypted,
            }))
            .expect("Sending to channel failed");
    });

    let accept_key_data = receiver.await??;
    let recipient_pub_key_id_used_by_sender =
        (&invitation_info.recipient_public_key_id_used_by_sender).try_into()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    let invite_id = match container_dao
        .invite_user(
            &invitation_info.recipient_user_email,
            &invitation_info.sender_public_key,
            &invitation_info.encryption_key_encrypted,
            &invitation_info.container_info_encrypted,
            &invitation_info.sender_info_encrypted,
            &invitation_info.share_info_symmetric_key_encrypted,
            recipient_pub_key_id_used_by_sender,
            recipient_pub_key_id,
            container_access_token.0.claims.container_id,
            expiration,
            invitation_info.read_only,
            accept_key_data.key_id,
            &accept_key_data.key_id_encrypted,
            &accept_key_data.public_key,
            &accept_key_data.private_key_encrypted,
            &accept_key_data.key_info_encrypted,
        )
        .await
    {
        Ok(i) => i,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container or invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to share container",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(invite_id)?)
}

pub async fn retract_invitation(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    invite_sender_token: SpecialAccessToken<ContainerInviteSenderToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let invitation_id = invite_sender_token.0.claims.invite_id;

    let container_dao = db::container::Dao::new(&db_async_pool);
    let invite_sender_public_key = match container_dao
        .get_container_invite_sender_public_key(invitation_id)
        .await
    {
        Ok(k) => k,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No invitation with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to get public container access key",
                )));
            }
        },
    };

    invite_sender_token.0.verify(&invite_sender_public_key)?;

    match container_dao.delete_invitation(invitation_id).await {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to delete invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_invitation(
    db_async_pool: web::Data<DbAsyncPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<ContainerAcceptToken, FromHeader>,
    container_user_public_key: ProtoBuf<PublicKey>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if container_user_public_key.value.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Public key too large",
        )));
    }

    let key_id = accept_token.0.claims.key_id;
    let container_id = accept_token.0.claims.container_id;
    let invite_id = accept_token.0.claims.invite_id;

    let container_dao = db::container::Dao::new(&db_async_pool);
    let container_accept_key = match container_dao
        .get_container_accept_public_key(key_id, container_id)
        .await
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to accept invitation",
                )));
            }
        },
    };

    if container_accept_key.expiration < SystemTime::now() {
        return Err(HttpErrorResponse::OutOfDate(Cow::Borrowed(
            "Invitation has expired",
        )));
    }

    accept_token.0.verify(&container_accept_key.public_key)?;

    let container_keys = match container_dao
        .accept_invitation(
            container_accept_key.key_id,
            container_accept_key.container_id,
            container_accept_key.read_only,
            invite_id,
            &user_access_token.0.user_email,
            &container_user_public_key.value,
        )
        .await
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to accept invitation",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(container_keys)?)
}

pub async fn decline_invitation(
    db_async_pool: web::Data<DbAsyncPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<ContainerAcceptToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let key_id = accept_token.0.claims.key_id;
    let container_id = accept_token.0.claims.container_id;
    let invite_id = accept_token.0.claims.invite_id;

    let container_dao = db::container::Dao::new(&db_async_pool);
    let container_accept_key = match container_dao
        .get_container_accept_public_key(key_id, container_id)
        .await
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to decline invitation",
                )));
            }
        },
    };

    accept_token.0.verify(&container_accept_key.public_key)?;

    match container_dao
        .reject_invitation(invite_id, key_id, &user_access_token.0.user_email)
        .await
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to decline invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_invitations(
    db_async_pool: web::Data<DbAsyncPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let container_dao = db::container::Dao::new(&db_async_pool);
    let invites = match container_dao
        .get_all_pending_invitations(&user_access_token.0.user_email)
        .await
    {
        Ok(invites) => invites,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().protobuf(ContainerAccessTokenList::default())?);
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to find invitations",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(invites)?)
}

pub async fn leave_container(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_access(&container_access_token, &db_async_pool).await?;

    let container_id = container_access_token.0.claims.container_id;
    let key_id = container_access_token.0.claims.key_id;

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao.leave_container(container_id, key_id).await {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container with ID matching token"),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to remove association with container",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_entry(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    entry_data: ProtoBuf<EncryptedBlobAndCategoryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    let entry_data = entry_data.0;
    let container_id = container_access_token.0.claims.container_id;

    if entry_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted blob too large",
        )));
    }

    // Actually optional
    let category_id = entry_data
        .category_id
        .as_ref()
        .map(Uuid::try_from)
        .transpose()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    let entry_id = match container_dao
        .create_entry(
            &entry_data.encrypted_blob,
            entry_data.version_nonce,
            category_id,
            container_id,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("There was an ID mismatch for the container, entry, or category"),
                    DoesNotExistType::Entry,
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                _,
            )) => {
                return Err(HttpErrorResponse::ForeignKeyDoesNotExist(Cow::Borrowed(
                    "No category matching ID",
                )))
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to create entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().protobuf(EntryId {
        value: entry_id.into(),
    })?)
}

pub async fn create_entry_and_category(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    entry_and_category_data: ProtoBuf<EntryAndCategory>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if entry_and_category_data.entry_encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Entry encrypted blob too large",
        )));
    }

    if entry_and_category_data.category_encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Category encrypted blob too large",
        )));
    }

    let container_dao = db::container::Dao::new(&db_async_pool);
    let entry_and_category_ids = match container_dao
        .create_entry_and_category(
            &entry_and_category_data.entry_encrypted_blob,
            entry_and_category_data.entry_version_nonce,
            &entry_and_category_data.category_encrypted_blob,
            entry_and_category_data.category_version_nonce,
            container_access_token.0.claims.container_id,
        )
        .await
    {
        Ok(ids) => ids,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container with ID matching token"),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to create entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().protobuf(entry_and_category_ids)?)
}

pub async fn edit_entry(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    entry_data: ProtoBuf<EntryUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if entry_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted blob too large",
        )));
    }

    let category_id = entry_data
        .category_id
        .as_ref()
        .map(Uuid::try_from)
        .transpose()?;

    let entry_id = (&entry_data.entry_id).try_into()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao
        .update_entry(
            entry_id,
            &entry_data.encrypted_blob,
            entry_data.version_nonce,
            entry_data.expected_previous_version_nonce,
            category_id,
            container_access_token.0.claims.container_id,
        )
        .await
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(Cow::Borrowed(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("Entry not found"),
                    DoesNotExistType::Entry,
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                _,
            )) => {
                return Err(HttpErrorResponse::ForeignKeyDoesNotExist(Cow::Borrowed(
                    "No category matching ID",
                )))
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to update entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_entry(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    entry_id: ProtoBuf<EntryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    let entry_id = (&entry_id.value).try_into()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao
        .soft_delete_entry(entry_id, container_access_token.0.claims.container_id)
        .await
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("Entry not found"),
                    DoesNotExistType::Entry,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to delete entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_category(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    category_data: ProtoBuf<NewEncryptedBlob>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if category_data.value.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted blob too large",
        )));
    }

    let container_dao = db::container::Dao::new(&db_async_pool);
    let category_id = match container_dao
        .create_category(
            &category_data.value,
            category_data.version_nonce,
            container_access_token.0.claims.container_id,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container with ID matching token"),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to create category",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().protobuf(CategoryId {
        value: category_id.into(),
    })?)
}

pub async fn edit_category(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    category_data: ProtoBuf<CategoryUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    if category_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(Cow::Borrowed(
            "Encrypted blob too large",
        )));
    }

    let category_id = (&category_data.category_id).try_into()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao
        .update_category(
            category_id,
            &category_data.encrypted_blob,
            category_data.version_nonce,
            category_data.expected_previous_version_nonce,
            container_access_token.0.claims.container_id,
        )
        .await
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(Cow::Borrowed(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("Category not found"),
                    DoesNotExistType::Category,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to update category",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_category(
    db_async_pool: web::Data<DbAsyncPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    container_access_token: SpecialAccessToken<ContainerAccessToken, FromHeader>,
    category_id: ProtoBuf<CategoryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&container_access_token, &db_async_pool).await?;

    let category_id = (&category_id.value).try_into()?;

    let container_dao = db::container::Dao::new(&db_async_pool);
    match container_dao
        .soft_delete_category(category_id, container_access_token.0.claims.container_id)
        .await
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("Category not found"),
                    DoesNotExistType::Category,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to delete category",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

async fn obtain_public_key(
    key_id: Uuid,
    container_id: Uuid,
    db_async_pool: &DbAsyncPool,
) -> Result<ContainerAccessKey, HttpErrorResponse> {
    let container_dao = db::container::Dao::new(db_async_pool);
    let key = match container_dao
        .get_public_container_key(key_id, container_id)
        .await
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    Cow::Borrowed("No container with ID matching token"),
                    DoesNotExistType::Container,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(Cow::Borrowed(
                    "Failed to get public container access key",
                )));
            }
        },
    };

    Ok(key)
}

async fn verify_read_write_access<F: TokenLocation>(
    container_access_token: &SpecialAccessToken<ContainerAccessToken, F>,
    db_async_pool: &DbAsyncPool,
) -> Result<(), HttpErrorResponse> {
    let claims = &container_access_token.0.claims;
    let public_key = obtain_public_key(claims.key_id, claims.container_id, db_async_pool).await?;
    container_access_token.0.verify(&public_key.public_key)?;

    if public_key.read_only {
        return Err(HttpErrorResponse::ReadOnlyAccess(Cow::Borrowed(
            "User has read-only access to container",
        )));
    }

    Ok(())
}

async fn verify_read_access<F: TokenLocation>(
    container_access_token: &SpecialAccessToken<ContainerAccessToken, F>,
    db_async_pool: &DbAsyncPool,
) -> Result<(), HttpErrorResponse> {
    let claims = &container_access_token.0.claims;
    let public_key = obtain_public_key(claims.key_id, claims.container_id, db_async_pool).await?;
    container_access_token.0.verify(&public_key.public_key)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use super::*;

    use entries_common::messages::{CategoryWithTempId, ContainerFrame};
    use entries_common::messages::{
        ContainerIdAndEncryptionKey, ContainerList, ContainerShareInviteList, EntryIdAndCategoryId,
        ErrorType, InvitationId, ServerErrorResponse, Uuid as UuidMessage,
    };
    use entries_common::models::container::Container;
    use entries_common::schema::categories::dsl::categories;
    use entries_common::schema::container_access_keys as container_access_key_fields;
    use entries_common::schema::container_access_keys::dsl::container_access_keys;
    use entries_common::schema::containers::dsl::containers;
    use entries_common::schema::entries::dsl::entries;
    use entries_common::schema::users as user_fields;
    use entries_common::schema::users::dsl::users;

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use diesel::{ExpressionMethods, QueryDsl};
    use ed25519_dalek as ed25519;
    use ed25519_dalek::Signer;
    use entries_common::threadrand::SecureRng;
    use entries_common::token::container_accept_token::ContainerAcceptTokenClaims;
    use entries_common::token::container_invite_sender_token::ContainerInviteSenderTokenClaims;
    use prost::Message;

    use crate::env;
    use crate::handlers::test_utils::{self, gen_bytes, gen_container_token};
    use crate::services::api::RouteLimiters;

    #[actix_rt::test]
    async fn test_create_and_get_container_and_entry_and_category() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: SecureRng::next_i64(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: SecureRng::next_i64(),
                },
            ],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let mut container_data = ContainerFrame::decode(resp_body).unwrap();
        container_data
            .category_ids
            .sort_unstable_by(|a, b| a.temp_id.cmp(&b.temp_id));

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_ids = container_data
            .category_ids
            .into_iter()
            .map(|c| Uuid::try_from(c.real_id).unwrap())
            .collect::<Vec<_>>();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 2);

        let categories_iter = container_message
            .categories
            .iter()
            .zip(new_container.categories.iter());

        let mut initial_categories = Vec::new();
        for (i, (category_message, category)) in categories_iter.enumerate() {
            assert_eq!(
                Uuid::try_from(&category_message.id).unwrap(),
                category_ids[i],
            );
            assert_eq!(category_message.encrypted_blob, category.encrypted_blob);
            assert_eq!(category_message.version_nonce, category.version_nonce);

            initial_categories.push((
                Uuid::try_from(&category_message.id).unwrap(),
                category_message.encrypted_blob.clone(),
            ));
        }

        assert_eq!(container_message.entries.len(), 0);

        let new_category = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_category_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 3);

        for category in container_message.categories.iter() {
            let curr_category_id: Uuid = (&category.id).try_into().unwrap();

            if curr_category_id == new_category_id {
                assert_eq!(category.encrypted_blob, new_category.value);
                assert_eq!(category.version_nonce, new_category.version_nonce);
            } else {
                let (_, preexisting_category_blob) = initial_categories
                    .iter()
                    .find(|c| c.0 == curr_category_id)
                    .unwrap();

                assert_eq!(preexisting_category_blob, &category.encrypted_blob);
            }
        }

        assert_eq!(container_message.entries.len(), 0);

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(new_category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_id: Uuid = EntryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 3);

        for category in container_message.categories.iter() {
            let curr_category_id: Uuid = (&category.id).try_into().unwrap();

            if curr_category_id == new_category_id {
                assert_eq!(category.encrypted_blob, new_category.value);
                assert_eq!(category.version_nonce, new_category.version_nonce);
            } else {
                let (_, preexisting_category_blob) = initial_categories
                    .iter()
                    .find(|c| c.0 == curr_category_id)
                    .unwrap();

                assert_eq!(preexisting_category_blob, &category.encrypted_blob);
            }
        }

        assert_eq!(container_message.entries.len(), 1);

        assert_eq!(
            Uuid::try_from(&container_message.entries[0].id).unwrap(),
            new_entry_id,
        );
        assert_eq!(
            Uuid::try_from(container_message.entries[0].category_id.clone().unwrap()).unwrap(),
            new_category_id,
        );
        assert_eq!(
            container_message.entries[0].encrypted_blob,
            new_entry.encrypted_blob,
        );
        assert_eq!(
            container_message.entries[0].version_nonce,
            new_entry.version_nonce,
        );

        let new_entry2 = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: None,
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry2.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry2_id: Uuid = EntryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(container_message.entries.len(), 2);

        let first_entry = container_message
            .entries
            .iter()
            .find(|e| Uuid::try_from(&e.id).unwrap() == new_entry_id)
            .unwrap();
        let second_entry = container_message
            .entries
            .iter()
            .find(|e| Uuid::try_from(&e.id).unwrap() == new_entry2_id)
            .unwrap();

        assert_eq!(first_entry.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(first_entry.version_nonce, new_entry.version_nonce);
        assert_eq!(second_entry.encrypted_blob, new_entry2.encrypted_blob);
        assert_eq!(second_entry.version_nonce, new_entry2.version_nonce);

        assert_eq!(
            Uuid::try_from(first_entry.category_id.clone().unwrap()).unwrap(),
            new_category_id,
        );

        assert!(second_entry.category_id.is_none());

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: gen_bytes(30),
            entry_version_nonce: SecureRng::next_i64(),
            category_encrypted_blob: gen_bytes(12),
            category_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_and_category_ids = EntryIdAndCategoryId::decode(resp_body).unwrap();

        let new_entry3_id: Uuid = new_entry_and_category_ids.entry_id.try_into().unwrap();
        let new_category4_id: Uuid = new_entry_and_category_ids.category_id.try_into().unwrap();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 4);
        assert_eq!(container_message.entries.len(), 3);

        let new_category4 = container_message
            .categories
            .iter()
            .find(|c| Uuid::try_from(&c.id).unwrap() == new_category4_id)
            .unwrap();

        let new_entry3 = container_message
            .entries
            .iter()
            .find(|e| Uuid::try_from(&e.id).unwrap() == new_entry3_id)
            .unwrap();

        assert_eq!(
            new_category4.encrypted_blob,
            new_entry_and_category.category_encrypted_blob
        );
        assert_eq!(
            new_category4.version_nonce,
            new_entry_and_category.category_version_nonce
        );
        assert_eq!(
            new_entry3.encrypted_blob,
            new_entry_and_category.entry_encrypted_blob
        );
        assert_eq!(
            new_entry3.version_nonce,
            new_entry_and_category.entry_version_nonce
        );
        assert_eq!(
            Uuid::try_from(new_entry3.category_id.clone().unwrap()).unwrap(),
            new_category4_id
        );
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_create_container_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let new_container = NewContainer {
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: SecureRng::next_i64(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: SecureRng::next_i64(),
                },
            ],
            user_public_container_key: gen_bytes(40),
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: SecureRng::next_i64(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: SecureRng::next_i64(),
                },
            ],
            user_public_container_key: vec![0; env::CONF.max_encryption_key_size + 1],
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_create_entry_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_id: Uuid = (&container_data.category_ids[0].real_id)
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_create_entry_and_category_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (_, container_token) = test_utils::create_container(&access_token).await;

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            entry_version_nonce: SecureRng::next_i64(),
            category_encrypted_blob: gen_bytes(12),
            category_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: gen_bytes(30),
            entry_version_nonce: SecureRng::next_i64(),
            category_encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            category_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_create_category_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let new_category = NewEncryptedBlob {
            value: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_get_multiple_containers() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (container1, container1_token) = test_utils::create_container(&access_token).await;
        let (container2, container2_token) = test_utils::create_container(&access_token).await;
        let (container3, container3_token) = test_utils::create_container(&access_token).await;

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: gen_bytes(30),
            entry_version_nonce: SecureRng::next_i64(),
            category_encrypted_blob: gen_bytes(12),
            category_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container3_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_and_category_ids = EntryIdAndCategoryId::decode(resp_body).unwrap();

        let new_entry_id: Uuid = new_entry_and_category_ids.entry_id.try_into().unwrap();
        let new_category_id: Uuid = new_entry_and_category_ids.category_id.try_into().unwrap();

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container1_token, container2_token, container3_token],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_list = ContainerList::decode(resp_body).unwrap();

        let resp_container1 = container_list
            .containers
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == container1.id)
            .unwrap();
        let resp_container2 = container_list
            .containers
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == container2.id)
            .unwrap();
        let resp_container3 = container_list
            .containers
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == container3.id)
            .unwrap();

        assert_eq!(container_list.containers.len(), 3);

        assert_eq!(
            Uuid::try_from(resp_container1.id.clone()).unwrap(),
            container1.id
        );
        assert_eq!(resp_container1.encrypted_blob, container1.encrypted_blob);
        assert_eq!(resp_container1.version_nonce, container1.version_nonce);
        assert_eq!(resp_container1.categories.len(), 0);
        assert_eq!(resp_container1.entries.len(), 0);

        assert_eq!(
            Uuid::try_from(resp_container2.id.clone()).unwrap(),
            container2.id
        );
        assert_eq!(resp_container2.encrypted_blob, container2.encrypted_blob);
        assert_eq!(resp_container2.version_nonce, container2.version_nonce);
        assert_eq!(resp_container2.categories.len(), 0);
        assert_eq!(resp_container2.entries.len(), 0);

        assert_eq!(
            Uuid::try_from(resp_container3.id.clone()).unwrap(),
            container3.id
        );
        assert_eq!(resp_container3.encrypted_blob, container3.encrypted_blob);
        assert_eq!(resp_container3.version_nonce, container3.version_nonce);
        assert_eq!(resp_container3.categories.len(), 1);
        assert_eq!(resp_container3.entries.len(), 1);

        assert_eq!(
            Uuid::try_from(&resp_container3.categories[0].id).unwrap(),
            new_category_id
        );
        assert_eq!(
            Uuid::try_from(&resp_container3.categories[0].container_id).unwrap(),
            container3.id
        );
        assert_eq!(
            resp_container3.categories[0].encrypted_blob,
            new_entry_and_category.category_encrypted_blob
        );
        assert_eq!(
            resp_container3.categories[0].version_nonce,
            new_entry_and_category.category_version_nonce
        );

        assert_eq!(
            Uuid::try_from(&resp_container3.entries[0].id).unwrap(),
            new_entry_id
        );
        assert_eq!(
            Uuid::try_from(&resp_container3.entries[0].container_id).unwrap(),
            container3.id
        );
        assert_eq!(
            Uuid::try_from(resp_container3.entries[0].category_id.as_ref().unwrap()).unwrap(),
            new_category_id
        );
        assert_eq!(
            resp_container3.entries[0].encrypted_blob,
            new_entry_and_category.entry_encrypted_blob
        );
        assert_eq!(
            resp_container3.entries[0].version_nonce,
            new_entry_and_category.entry_version_nonce
        );

        let mut tokens = Vec::with_capacity(101);
        for i in 0..101 {
            tokens.push(format!("faketoken{}", i));
        }
        let container_access_tokens = ContainerAccessTokenList { tokens };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::TooManyRequested as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_get_multiple_containers_fails_with_too_many_tokens() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![String::from("test"); env::CONF.max_container_fetch_count + 1],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::TooManyRequested as i32);
    }

    #[actix_rt::test]
    async fn test_delete_category() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_id: Uuid = (&container_data.category_ids[0].real_id)
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);

        assert_eq!(container_message.categories.len(), 1);

        let category_message = &container_message.categories[0];

        assert_eq!(Uuid::try_from(&category_message.id).unwrap(), category_id,);
        assert_eq!(
            category_message.encrypted_blob,
            new_container.categories[0].encrypted_blob
        );

        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category_id,
        );

        let category_id_message = CategoryId {
            value: category_id.into(),
        };

        let req = TestRequest::delete()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_id_message.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);

        // Category is soft-deleted, so it's returned as a stub with empty blob
        assert_eq!(container_message.categories.len(), 1);
        assert_eq!(
            container_message.categories[0].encrypted_blob,
            Vec::<u8>::new()
        );
        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert!(entry_message.category_id.is_none());
    }

    #[actix_rt::test]
    async fn test_delete_entry() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519_dalek::SigningKey::generate(SecureRng::get_ref());
        let public_key = key_pair.verifying_key().to_bytes().to_vec();

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_id: Uuid = (&container_data.category_ids[0].real_id)
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);

        assert_eq!(container_message.categories.len(), 1);
        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category_id,
        );

        let entry_id: Uuid = (&entry_message.id).try_into().unwrap();

        let entry_id_message = EntryId {
            value: entry_id.into(),
        };

        let req = TestRequest::delete()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_id_message.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);

        // Entry is soft-deleted, so it's returned as a stub with empty blob
        assert_eq!(container_message.categories.len(), 1);
        assert_eq!(container_message.entries.len(), 1);
        assert_eq!(
            container_message.entries[0].encrypted_blob,
            Vec::<u8>::new()
        );
    }

    #[actix_rt::test]
    async fn test_get_soft_deleted_container() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: SecureRng::next_i64(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(50),
                    version_nonce: SecureRng::next_i64(),
                },
            ],
            user_public_container_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();

        let container = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        // Create some entries
        let category_id: Uuid = (&container_data.category_ids[0].real_id)
            .try_into()
            .unwrap();

        let new_entry1 = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry1.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let new_entry2 = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(25),
            version_nonce: SecureRng::next_i64(),
            category_id: None,
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry2.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify container has categories and entries before soft deletion
        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(container_message.categories.len(), 2);
        assert_eq!(container_message.entries.len(), 2);

        // Soft delete the container
        let container_dao = db::container::Dao::new(&env::testing::DB_ASYNC_POOL);
        container_dao
            .soft_delete_container(container.id)
            .await
            .unwrap();

        // Verify that after soft deletion, categories and entries are empty
        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_access_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        // Container blob should be empty after soft deletion and it shouldn't return any
        // categories or entries
        assert_eq!(container_message.encrypted_blob, Vec::<u8>::new());
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);
        assert!(container_message.deleted_at.is_some());
    }

    #[actix_rt::test]
    async fn test_get_multiple_containers_with_soft_deleted() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair1 = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key1 = Vec::from(key_pair1.verifying_key().to_bytes());

        let new_container1 = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key1,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container1.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data1 = ContainerFrame::decode(resp_body).unwrap();

        let container1 = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data1.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token1 = gen_container_token(
            container1.id,
            container_data1.access_key_id.try_into().unwrap(),
            &key_pair1,
        );

        let category_id1: Uuid = (&container_data1.category_ids[0].real_id)
            .try_into()
            .unwrap();

        let new_entry1 = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id1.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_access_token1.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry1.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let key_pair2 = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key2 = Vec::from(key_pair2.verifying_key().to_bytes());

        let new_container2 = NewContainer {
            encrypted_blob: gen_bytes(35),
            version_nonce: SecureRng::next_i64(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(45),
                version_nonce: SecureRng::next_i64(),
            }],
            user_public_container_key: public_key2,
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container2.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data2 = ContainerFrame::decode(resp_body).unwrap();

        let container2 = diesel_async::RunQueryDsl::get_result::<Container>(
            containers.find(Uuid::try_from(container_data2.id).unwrap()),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let container_access_token2 = gen_container_token(
            container2.id,
            container_data2.access_key_id.try_into().unwrap(),
            &key_pair2,
        );

        let container_dao = db::container::Dao::new(&env::testing::DB_ASYNC_POOL);
        container_dao
            .soft_delete_container(container1.id)
            .await
            .unwrap();

        let container_access_tokens = ContainerAccessTokenList {
            tokens: vec![container_access_token1, container_access_token2],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_list = ContainerList::decode(resp_body).unwrap();

        assert_eq!(container_list.containers.len(), 2);

        let deleted_container = container_list
            .containers
            .iter()
            .find(|c| Uuid::try_from(&c.id).unwrap() == container1.id)
            .unwrap();

        // Soft-deleted container should have empty categories and entries
        assert_eq!(deleted_container.categories.len(), 0);
        assert_eq!(deleted_container.entries.len(), 0);
        assert_eq!(deleted_container.encrypted_blob, Vec::<u8>::new());
        assert!(deleted_container.deleted_at.is_some());

        let active_container = container_list
            .containers
            .iter()
            .find(|c| Uuid::try_from(&c.id).unwrap() == container2.id)
            .unwrap();

        assert_eq!(active_container.categories.len(), 1);
        assert_eq!(active_container.entries.len(), 0);
        assert_eq!(active_container.encrypted_blob, container2.encrypted_blob);
        assert!(active_container.deleted_at.is_none());
    }

    #[actix_rt::test]
    async fn test_edit_container() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (container, container_token) = test_utils::create_container(&access_token).await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: container.version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: container.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, blob_update.encrypted_blob);
        assert_eq!(container_message.version_nonce, blob_update.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_edit_container_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (container, container_token) = test_utils::create_container(&access_token).await;

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: container.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_edit_entry() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (container, container_token) = test_utils::create_container(&access_token).await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);

        let new_category1 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category1.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category1_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_category2 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category2.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category2_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category2_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 2);
        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );

        let entry_id: Uuid = (&entry_message.id).try_into().unwrap();
        let mut expected_previous_version_nonce = entry_message.version_nonce;

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: expected_previous_version_nonce.wrapping_sub(1),
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let entry_update = EntryUpdate {
            entry_id: Uuid::now_v7().into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce,
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::EntryDoesNotExist as i32);

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce,
            category_id: Some(Uuid::now_v7().into()),
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(
            error_message.err_type,
            ErrorType::ForeignKeyDoesNotExist as i32
        );

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce,
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        expected_previous_version_nonce = entry_update.version_nonce;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.categories.len(), 2);
        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, entry_update.encrypted_blob);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category1_id,
        );

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: expected_previous_version_nonce.wrapping_add(1),
            category_id: None,
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce,
            category_id: None,
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.categories.len(), 2);
        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, entry_update.encrypted_blob);
        assert!(entry_message.category_id.is_none());
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_edit_entry_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (_, container_token) = test_utils::create_container(&access_token).await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let new_category = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        let entry_id: Uuid = (&entry_message.id).try_into().unwrap();
        let expected_previous_version_nonce = entry_message.version_nonce;

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce,
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_edit_category() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (container, container_token) = test_utils::create_container(&access_token).await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);

        let new_category1 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category1.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category1_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_category2 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category2.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category2_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category2_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 2);

        let cat1_pos = container_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(
            container_message.categories[cat1_pos].id,
            category1_id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            container_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(
            container_message.categories[cat2_pos].id,
            category2_id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].encrypted_blob,
            new_category2.value
        );
        assert_eq!(
            container_message.categories[cat2_pos].version_nonce,
            new_category2.version_nonce
        );

        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );

        let category_update = CategoryUpdate {
            category_id: category2_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: new_category2.version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let category_update = CategoryUpdate {
            category_id: Uuid::now_v7().into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: new_category2.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(
            error_message.err_type,
            ErrorType::CategoryDoesNotExist as i32
        );

        let category_update = CategoryUpdate {
            category_id: category2_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: new_category2.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 2);

        let cat1_pos = container_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(
            container_message.categories[cat1_pos].id,
            category1_id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            container_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(
            container_message.categories[cat2_pos].id,
            category2_id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].encrypted_blob,
            category_update.encrypted_blob
        );
        assert_eq!(
            container_message.categories[cat2_pos].version_nonce,
            category_update.version_nonce
        );

        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );

        let category_update_version_nonce = category_update.version_nonce;

        let category_update = CategoryUpdate {
            category_id: category2_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: category_update_version_nonce.wrapping_sub(1),
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let category_update = CategoryUpdate {
            category_id: category2_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: category_update_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);

        assert_eq!(container_message.categories.len(), 2);

        let cat1_pos = container_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(
            container_message.categories[cat1_pos].id,
            category1_id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            container_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(
            container_message.categories[cat2_pos].id,
            category2_id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].container_id,
            container.id.into()
        );
        assert_eq!(
            container_message.categories[cat2_pos].encrypted_blob,
            category_update.encrypted_blob
        );
        assert_eq!(
            container_message.categories[cat2_pos].version_nonce,
            category_update.version_nonce
        );

        assert_eq!(container_message.entries.len(), 1);

        let entry_message = &container_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_edit_category_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (_, container_token) = test_utils::create_container(&access_token).await;

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let new_category = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let category_update = CategoryUpdate {
            category_id: category_id.into(),
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: new_category.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("ContainerAccessToken", container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_invite_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id).await;

        let (container, sender_container_token) =
            test_utils::create_container(&sender_access_token).await;
        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        assert_eq!(invites.len(), 1);
        assert_eq!(
            recipient.public_key_id,
            <&UuidMessage as TryInto<Uuid>>::try_into(
                &invites[0].recipient_public_key_id_used_by_sender
            )
            .unwrap()
        );
        assert_eq!(
            recipient.public_key_id,
            <&UuidMessage as TryInto<Uuid>>::try_into(
                &invites[0].recipient_public_key_id_used_by_server
            )
            .unwrap()
        );

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = ContainerAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            container_id: container.id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_private_key =
            ed25519::SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let mut token = accept_token_claims.clone();
        let signature = accept_private_key.sign(&accept_token_claims).to_bytes();
        token.extend_from_slice(&signature);
        let mut bad_token = token.clone();
        let accept_token = b64_urlsafe.encode(token);

        let access_private_key = ed25519::SigningKey::generate(SecureRng::get_ref());
        let access_public_key = Vec::from(access_private_key.verifying_key().to_bytes());
        let access_public_key = PublicKey {
            value: access_public_key,
        };

        // Make the signature invalid
        let last_byte = bad_token.pop().unwrap();
        if last_byte == 0x01 {
            bad_token.push(0x02);
        } else {
            bad_token.push(0x01);
        }
        let bad_token = b64_urlsafe.encode(bad_token);

        let req = TestRequest::put()
            .uri("/api/container/invitation/accept")
            .insert_header(("ContainerAcceptToken", bad_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::put()
            .uri("/api/container/invitation/accept")
            .insert_header(("ContainerAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let message = ContainerIdAndEncryptionKey::decode(resp_body).unwrap();

        assert_eq!(message.container_id, container.id.into());
        assert_eq!(
            message.encryption_key_encrypted,
            invite_info.encryption_key_encrypted
        );
        assert_eq!(message.read_only, invite_info.read_only);

        let access_key_id = Uuid::try_from(message.container_access_key_id).unwrap();
        let recipient_container_token =
            gen_container_token(container.id, access_key_id, &access_private_key);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token[..10].to_string()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_ne!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(&container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, container.encrypted_blob);
        assert_eq!(container_message.version_nonce, container.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            expected_previous_version_nonce: container.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("ContainerAccessToken", recipient_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        diesel_async::RunQueryDsl::execute(
            diesel::update(container_access_keys.find((access_key_id, container.id)))
                .set(container_access_key_fields::read_only.eq(false)),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let req = TestRequest::put()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("ContainerAccessToken", recipient_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_message = ContainerList::decode(resp_body).unwrap().containers[0].clone();

        assert_eq!(Uuid::try_from(container_message.id).unwrap(), container.id);
        assert_eq!(container_message.encrypted_blob, blob_update.encrypted_blob);
        assert_eq!(container_message.version_nonce, blob_update.version_nonce);
        assert_eq!(container_message.categories.len(), 0);
        assert_eq!(container_message.entries.len(), 0);
        assert_eq!(container_message.version_nonce, blob_update.version_nonce);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_invite_user_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, _, _, _) = test_utils::create_user().await;
        let (_, sender_container_token) = test_utils::create_container(&sender_access_token).await;

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: vec![0; env::CONF.max_encryption_key_size + 1],
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("ContainerAccessToken", sender_container_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: vec![0; env::CONF.max_encryption_key_size + 1],
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("ContainerAccessToken", sender_container_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("ContainerAccessToken", sender_container_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("ContainerAccessToken", sender_container_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("ContainerAccessToken", sender_container_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: vec![0; env::CONF.max_encryption_key_size + 1],
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_invite_user_fails_invalid_recipient_email_address() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, _, _, _) = test_utils::create_user().await;
        let (_, sender_container_token) = test_utils::create_container(&sender_access_token).await;

        let invite_info = UserInvitationToContainer {
            recipient_user_email: "invalid_email_address".to_string(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::IncorrectlyFormed as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_accept_invitation_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id).await;

        let (container, sender_container_token) =
            test_utils::create_container(&sender_access_token).await;
        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = ContainerAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            container_id: container.id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_private_key =
            ed25519::SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let mut token = accept_token_claims.clone();
        let signature = accept_private_key.sign(&accept_token_claims).to_bytes();
        token.extend_from_slice(&signature);
        let accept_token = b64_urlsafe.encode(token);

        let access_public_key = PublicKey {
            value: vec![0; env::CONF.max_encryption_key_size + 1],
        };

        let req = TestRequest::put()
            .uri("/api/container/invitation/accept")
            .insert_header(("ContainerAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_retract_invitation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;
        let (_, sender_container_token) = test_utils::create_container(&sender_access_token).await;

        let recipient_keypair = Rsa::generate(512).unwrap();
        let recipient_public_key = recipient_keypair.public_key_to_der().unwrap();

        diesel_async::RunQueryDsl::execute(
            diesel::update(users.find(recipient.id))
                .set(user_fields::public_key.eq(recipient_public_key.to_vec())),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        let invite_sender_keypair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let invite_sender_pub_key = invite_sender_keypair.verifying_key().to_bytes();

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: invite_sender_pub_key.to_vec(),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(60))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerAccessToken", sender_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invite_id = InvitationId::decode(resp_body).unwrap();

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        assert_eq!(invites.len(), 1);

        let claims = ContainerInviteSenderTokenClaims {
            invite_id: invite_id.value.try_into().unwrap(),
            expiration: (SystemTime::now() + Duration::from_secs(100))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let claims = serde_json::to_vec(&claims).unwrap();

        let mut token = claims.clone();
        let signature = invite_sender_keypair.sign(&claims).to_bytes();
        token.extend_from_slice(&signature);
        let invite_sender_token = b64_urlsafe.encode(token);

        let req = TestRequest::delete()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::delete()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header((
                "ContainerInviteSenderToken",
                sender_container_token.as_str(),
            ))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::delete()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerInviteSenderToken", invite_sender_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        assert!(invites.is_empty());
    }

    #[actix_rt::test]
    async fn test_decline_invitation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id).await;
        let (container, sender_container_token) =
            test_utils::create_container(&sender_access_token).await;

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = ContainerAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            container_id: container.id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_private_key =
            ed25519::SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let mut token = accept_token_claims.clone();
        let signature = accept_private_key.sign(&accept_token_claims).to_bytes();
        token.extend_from_slice(&signature);
        let mut bad_token = token.clone();
        let accept_token = b64_urlsafe.encode(token);

        let access_private_key = ed25519::SigningKey::generate(SecureRng::get_ref());
        let access_public_key = Vec::from(access_private_key.to_bytes());
        let access_public_key = PublicKey {
            value: access_public_key,
        };

        // Make the signature invalid
        let last_byte = bad_token.pop().unwrap();
        if last_byte == 0x01 {
            bad_token.push(0x02);
        } else {
            bad_token.push(0x01);
        }
        let bad_token = b64_urlsafe.encode(bad_token);

        let req = TestRequest::put()
            .uri("/api/container/invitation/decline")
            .insert_header(("ContainerAcceptToken", bad_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::put()
            .uri("/api/container/invitation/decline")
            .insert_header(("ContainerAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        assert!(invites.is_empty());
    }

    #[actix_rt::test]
    async fn test_leave_container() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_ASYNC_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id).await;

        let (container, sender_container_token) =
            test_utils::create_container(&sender_access_token).await;

        // Create some entries and categories to test soft deletion
        let new_category = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/container/category")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerAccessToken", sender_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let category_id: Uuid = CategoryId::decode(resp_body)
            .unwrap()
            .value
            .try_into()
            .unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: SecureRng::next_i64(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/container/entry")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerAccessToken", sender_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let invite_info = UserInvitationToContainer {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerAccessToken", sender_container_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = ContainerAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            container_id: container.id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_private_key =
            ed25519::SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let mut token = accept_token_claims.clone();
        let signature = accept_private_key.sign(&accept_token_claims).to_bytes();
        token.extend_from_slice(&signature);
        let accept_token = b64_urlsafe.encode(token);

        let access_private_key = ed25519::SigningKey::generate(SecureRng::get_ref());
        let access_public_key = Vec::from(access_private_key.verifying_key().to_bytes());
        let access_public_key = PublicKey {
            value: access_public_key,
        };

        let req = TestRequest::put()
            .uri("/api/container/invitation/accept")
            .insert_header(("ContainerAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let message = ContainerIdAndEncryptionKey::decode(resp_body).unwrap();

        assert_eq!(message.container_id, container.id.into());
        assert_eq!(
            message.encryption_key_encrypted,
            invite_info.encryption_key_encrypted
        );
        assert_eq!(message.read_only, invite_info.read_only);

        let access_key_id = Uuid::try_from(message.container_access_key_id).unwrap();
        let recipient_container_token =
            gen_container_token(container.id, access_key_id, &access_private_key);

        // Check both sender and recipient can access the container
        let container_token_list = ContainerAccessTokenList {
            tokens: vec![sender_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_access_key_count = diesel_async::RunQueryDsl::get_result::<i64>(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container.id))
                .count(),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(container_access_key_count, 2);

        let req = TestRequest::delete()
            .uri("/api/container/leave")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("ContainerAccessToken", sender_container_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_access_key_count = diesel_async::RunQueryDsl::get_result::<i64>(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container.id))
                .count(),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(container_access_key_count, 1);

        // Check recipient can access the container but sender no longer has access
        let container_token_list = ContainerAccessTokenList {
            tokens: vec![sender_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let result = diesel_async::RunQueryDsl::first::<Container>(
            containers.find(container.id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await;
        assert!(result.is_ok());

        let req = TestRequest::delete()
            .uri("/api/container/leave")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("ContainerAccessToken", recipient_container_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let container_access_key_count = diesel_async::RunQueryDsl::get_result::<i64>(
            container_access_keys
                .filter(container_access_key_fields::container_id.eq(container.id))
                .count(),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(container_access_key_count, 0);

        // Check both sender and recipient no longer have access to the container
        let container_token_list = ContainerAccessTokenList {
            tokens: vec![sender_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let container_token_list = ContainerAccessTokenList {
            tokens: vec![recipient_container_token.clone()],
        };

        let req = TestRequest::get()
            .uri("/api/container")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(container_token_list.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Verify container, entries, and categories are all hard-deleted (cascade delete)
        // Note: Since the user no longer has access, we can't use their token. But we can verify via direct DB query
        // that the container and all associated entries and categories no longer exist
        let container_from_db = diesel_async::RunQueryDsl::first::<Container>(
            containers.find(container.id),
            &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
        )
        .await;
        assert!(container_from_db.is_err());

        let categories_from_db: Vec<entries_common::models::category::Category> =
            diesel_async::RunQueryDsl::load(
                categories
                    .filter(entries_common::schema::categories::container_id.eq(container.id)),
                &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(categories_from_db.len(), 0);

        let entries_from_db: Vec<entries_common::models::entry::Entry> =
            diesel_async::RunQueryDsl::load(
                entries.filter(entries_common::schema::entries::container_id.eq(container.id)),
                &mut env::testing::DB_ASYNC_POOL.get().await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(entries_from_db.len(), 0);
    }
}
