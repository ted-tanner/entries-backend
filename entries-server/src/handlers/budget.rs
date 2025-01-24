use entries_common::messages::{
    AcceptKeyInfo, BudgetAccessTokenList, CategoryId, CategoryUpdate, EncryptedBlobAndCategoryId,
    EncryptedBlobUpdate, EntryAndCategory, EntryId, EntryUpdate, NewBudget, NewEncryptedBlob,
    PublicKey, UserInvitationToBudget,
};
use entries_common::models::budget_access_key::BudgetAccessKey;
use entries_common::token::budget_accept_token::BudgetAcceptToken;
use entries_common::token::budget_access_token::BudgetAccessToken;
use entries_common::token::budget_invite_sender_token::BudgetInviteSenderToken;
use entries_common::token::Token;
use entries_common::validators::{self, Validity};
use entries_common::{db, db::DaoError, db::DbThreadPool};

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{web, HttpResponse};
use ed25519_dalek as ed25519;
use openssl::rsa::{Padding, Rsa};
use prost::Message;
use rand::rngs::OsRng;
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
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_access(&budget_access_token, &db_thread_pool).await?;

    let budget = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_budget(budget_access_token.0.claims.budget_id)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get budget data",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(budget)?)
}

pub async fn get_multiple(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_tokens: ProtoBuf<BudgetAccessTokenList>,
) -> Result<HttpResponse, HttpErrorResponse> {
    const INVALID_ID_MSG: &str = "One of the provided budget access tokens had an invalid ID";

    if budget_access_tokens.tokens.len() > env::CONF.max_budget_fetch_count {
        return Err(HttpErrorResponse::TooManyRequested(format!(
            "Cannot fetch more than {} budgets at once",
            env::CONF.max_budget_fetch_count,
        )));
    }

    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut budget_ids = Vec::new();

    for token in budget_access_tokens.tokens.iter() {
        let token = BudgetAccessToken::decode(token)
            .map_err(|_| HttpErrorResponse::IncorrectlyFormed(String::from(INVALID_ID_MSG)))?;

        key_ids.push(token.claims.key_id);
        budget_ids.push(token.claims.budget_id);
        tokens.insert(token.claims.key_id, token);
    }

    let budget_ids = Arc::new(budget_ids);
    let budget_ids_ref = Arc::clone(&budget_ids);

    let budget_dao = db::budget::Dao::new(&db_thread_pool);
    let public_keys = match web::block(move || {
        budget_dao.get_multiple_public_budget_keys(&key_ids, &budget_ids_ref)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from(INVALID_ID_MSG),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get budget data",
                )));
            }
        },
    };

    if public_keys.len() != tokens.len() {
        return Err(HttpErrorResponse::DoesNotExist(
            String::from(INVALID_ID_MSG),
            DoesNotExistType::Budget,
        ));
    }

    for key in public_keys {
        let token = match tokens.get(&key.key_id) {
            Some(t) => t,
            None => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from(INVALID_ID_MSG),
                    DoesNotExistType::Budget,
                ))
            }
        };

        token.verify(&key.public_key)?;
    }

    let budgets = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_multiple_budgets_by_id(&budget_ids)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("One of the provided IDs did not match a budget"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get budget data",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(budgets)?)
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    budget_data: ProtoBuf<NewBudget>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    if budget_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Budget encrypted blob too large",
        )));
    }

    if budget_data.user_public_budget_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "User public key too large",
        )));
    }

    for category in budget_data.categories.iter() {
        if category.encrypted_blob.len() > env::CONF.max_small_object_size {
            return Err(HttpErrorResponse::InputTooLarge(format!(
                "Category encrypted blob too large for category with temp ID {}",
                category.temp_id,
            )));
        }
    }

    // temp_id is an ID the client generates that allows the server to differentiate between
    // categories when multiple are sent to the server simultaneously. The server doesn't have any
    // other way of differentiating them because they are encrypted.
    let temp_id_set = HashSet::<i32>::from_iter(budget_data.categories.iter().map(|c| c.temp_id));

    if temp_id_set.len() != budget_data.categories.len() {
        return Err(HttpErrorResponse::InvalidState(String::from(
            "Multiple categories with the same ID",
        )));
    }

    let new_budget = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_budget(
            &budget_data.encrypted_blob,
            budget_data.version_nonce,
            &budget_data.categories,
            &budget_data.user_public_budget_key,
        )
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("{e}");
            return Err(HttpErrorResponse::InternalError(String::from(
                "Failed to create budget",
            )));
        }
    };

    Ok(HttpResponse::Created().protobuf(new_budget)?)
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    budget_data: ProtoBuf<EncryptedBlobUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    if budget_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Budget encrypted blob too large",
        )));
    }

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_budget(
            budget_access_token.0.claims.budget_id,
            &budget_data.encrypted_blob,
            budget_data.version_nonce,
            budget_data.expected_previous_version_nonce,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(String::from(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to edit budget",
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
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    invitation_info: ProtoBuf<UserInvitationToBudget>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    if invitation_info.sender_public_key.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Sender public key too large",
        )));
    }

    if invitation_info.encryption_key_encrypted.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted encryption key too large",
        )));
    }

    if invitation_info.budget_info_encrypted.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Budget info encrypted too large",
        )));
    }

    if invitation_info.sender_info_encrypted.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Sender info encrypted too large",
        )));
    }

    if invitation_info.share_info_symmetric_key_encrypted.len() > env::CONF.max_encryption_key_size
    {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted symmetric key too large",
        )));
    }

    if let Validity::Invalid(msg) =
        validators::validate_email_address(&invitation_info.recipient_user_email)
    {
        return Err(HttpErrorResponse::IncorrectlyFormed(String::from(msg)));
    }

    if invitation_info.recipient_user_email == user_access_token.0.user_email {
        return Err(HttpErrorResponse::InvalidState(String::from(
            "Inviter and recipient are the same",
        )));
    }

    let read_only = invitation_info.read_only;
    let expiration: SystemTime = (&invitation_info.expiration).into();

    let invitation_info = Arc::new(invitation_info.0);
    let invitation_info_ref = Arc::clone(&invitation_info);

    let user_dao = db::user::Dao::new(&db_thread_pool);
    let (recipient_pub_key_id, recipient_public_key) = match web::block(move || {
        user_dao.get_user_public_key(&invitation_info_ref.recipient_user_email)
    })
    .await?
    {
        Ok(k) => (Uuid::try_from(k.id)?, k.value),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No user with given email"),
                    DoesNotExistType::User,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get recipient user's public key",
                )));
            }
        },
    };

    let (sender, receiver) = oneshot::channel();

    rayon::spawn(move || {
        let accept_key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let accept_public_key = accept_key_pair.verifying_key().to_bytes();
        let accept_private_key = accept_key_pair.as_bytes();

        let recipient_public_key = match Rsa::public_key_from_der(&recipient_public_key) {
            Ok(k) => k,
            Err(_) => {
                sender
                    .send(Err(HttpErrorResponse::IncorrectlyFormed(String::from(
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
                    .send(Err(HttpErrorResponse::InternalError(String::from(
                        "Failed to encrypt accept key pair using recipient's public key",
                    ))))
                    .expect("Sending to channel failed");

                return;
            }
        };
        private_key_encrypted.truncate(encrypted_size);

        let key_id = Uuid::new_v4();

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

    let invite_id = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.invite_user(
            &invitation_info.recipient_user_email,
            &invitation_info.sender_public_key,
            &invitation_info.encryption_key_encrypted,
            &invitation_info.budget_info_encrypted,
            &invitation_info.sender_info_encrypted,
            &invitation_info.share_info_symmetric_key_encrypted,
            recipient_pub_key_id_used_by_sender,
            recipient_pub_key_id,
            budget_access_token.0.claims.budget_id,
            expiration,
            invitation_info.read_only,
            accept_key_data.key_id,
            &accept_key_data.key_id_encrypted,
            &accept_key_data.public_key,
            &accept_key_data.private_key_encrypted,
            &accept_key_data.key_info_encrypted,
        )
    })
    .await?
    {
        Ok(i) => i,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget or invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to share budget",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(invite_id)?)
}

pub async fn retract_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    invite_sender_token: SpecialAccessToken<BudgetInviteSenderToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let invitation_id = invite_sender_token.0.claims.invite_id;

    let budget_dao = db::budget::Dao::new(&db_thread_pool);
    let invite_sender_public_key =
        match web::block(move || budget_dao.get_budget_invite_sender_public_key(invitation_id))
            .await?
        {
            Ok(k) => k,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        String::from("No invitation with ID matching token"),
                        DoesNotExistType::Invitation,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(String::from(
                        "Failed to get public budget access key",
                    )));
                }
            },
        };

    invite_sender_token.0.verify(&invite_sender_public_key)?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invite_sender_token.0.claims.invite_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to delete invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<BudgetAcceptToken, FromHeader>,
    budget_user_public_key: ProtoBuf<PublicKey>,
) -> Result<HttpResponse, HttpErrorResponse> {
    // TODO: Test
    if budget_user_public_key.value.len() > env::CONF.max_encryption_key_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Public key too large",
        )));
    }

    let key_id = accept_token.0.claims.key_id;
    let budget_id = accept_token.0.claims.budget_id;

    let budget_dao = db::budget::Dao::new(&db_thread_pool);
    let budget_accept_key =
        match web::block(move || budget_dao.get_budget_accept_public_key(key_id, budget_id)).await?
        {
            Ok(key) => key,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        String::from("No share invite with ID matching token"),
                        DoesNotExistType::Invitation,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(String::from(
                        "Failed to accept invitation",
                    )));
                }
            },
        };

    if budget_accept_key.expiration < SystemTime::now() {
        return Err(HttpErrorResponse::OutOfDate(String::from(
            "Invitation has expired",
        )));
    }

    accept_token.0.verify(&budget_accept_key.public_key)?;

    let budget_keys = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.accept_invitation(
            budget_accept_key.key_id,
            budget_accept_key.budget_id,
            budget_accept_key.read_only,
            accept_token.0.claims.invite_id,
            &user_access_token.0.user_email,
            &budget_user_public_key.value,
        )
    })
    .await?
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to accept invitation",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(budget_keys)?)
}

pub async fn decline_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<BudgetAcceptToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let key_id = accept_token.0.claims.key_id;
    let budget_id = accept_token.0.claims.budget_id;

    let budget_dao = db::budget::Dao::new(&db_thread_pool);
    let budget_accept_key =
        match web::block(move || budget_dao.get_budget_accept_public_key(key_id, budget_id)).await?
        {
            Ok(key) => key,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(HttpErrorResponse::DoesNotExist(
                        String::from("No share invite with ID matching token"),
                        DoesNotExistType::Invitation,
                    ));
                }
                _ => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(String::from(
                        "Failed to decline invitation",
                    )));
                }
            },
        };

    accept_token.0.verify(&budget_accept_key.public_key)?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.reject_invitation(
            accept_token.0.claims.invite_id,
            accept_token.0.claims.key_id,
            &user_access_token.0.user_email,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No share invite with ID matching token"),
                    DoesNotExistType::Invitation,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to decline invitation",
                )));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_invitations(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    let invites = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_pending_invitations(&user_access_token.0.user_email)
    })
    .await?
    {
        Ok(invites) => invites,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().protobuf(BudgetAccessTokenList::default())?);
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to find invitations",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().protobuf(invites)?)
}

pub async fn leave_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.leave_budget(
            budget_access_token.0.claims.budget_id,
            budget_access_token.0.claims.key_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to remove association with budget",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_data: ProtoBuf<EncryptedBlobAndCategoryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    // TODO: Test
    if entry_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted blob too large",
        )));
    }

    // Actually optional
    let category_id = entry_data
        .category_id
        .as_ref()
        .map(Uuid::try_from)
        .transpose()?;

    let entry_id = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry(
            &entry_data.0.encrypted_blob,
            entry_data.0.version_nonce,
            category_id,
            budget_access_token.0.claims.budget_id,
        )
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("There was an ID mismatch for the budget, entry, or category"),
                    DoesNotExistType::Entry,
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                _,
            )) => {
                return Err(HttpErrorResponse::ForeignKeyDoesNotExist(String::from(
                    "No category matching ID",
                )))
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
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
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_and_category_data: ProtoBuf<EntryAndCategory>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    // TODO: Test
    if entry_and_category_data.entry_encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Entry encrypted blob too large",
        )));
    }

    if entry_and_category_data.category_encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Category encrypted blob too large",
        )));
    }

    let entry_and_category_ids = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry_and_category(
            &entry_and_category_data.entry_encrypted_blob,
            entry_and_category_data.entry_version_nonce,
            &entry_and_category_data.category_encrypted_blob,
            entry_and_category_data.category_version_nonce,
            budget_access_token.0.claims.budget_id,
        )
    })
    .await?
    {
        Ok(ids) => ids,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to create entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Created().protobuf(entry_and_category_ids)?)
}

pub async fn edit_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_data: ProtoBuf<EntryUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    // TODO: Test
    if entry_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted blob too large",
        )));
    }

    let category_id = entry_data
        .category_id
        .as_ref()
        .map(Uuid::try_from)
        .transpose()?;

    let entry_id = (&entry_data.entry_id).try_into()?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_entry(
            entry_id,
            &entry_data.encrypted_blob,
            entry_data.version_nonce,
            entry_data.expected_previous_version_nonce,
            category_id,
            budget_access_token.0.claims.budget_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(String::from(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("Entry not found"),
                    DoesNotExistType::Entry,
                ));
            }
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                _,
            )) => {
                return Err(HttpErrorResponse::ForeignKeyDoesNotExist(String::from(
                    "No category matching ID",
                )))
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to update entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_id: ProtoBuf<EntryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let entry_id = (&entry_id.value).try_into()?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_entry(entry_id, budget_access_token.0.claims.budget_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("Entry not found"),
                    DoesNotExistType::Entry,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to delete entry",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_data: ProtoBuf<NewEncryptedBlob>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    // TODO: Test
    if category_data.value.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted blob too large",
        )));
    }

    let category_id = match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_category(
            &category_data.value,
            category_data.version_nonce,
            budget_access_token.0.claims.budget_id,
        )
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
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
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_data: ProtoBuf<CategoryUpdate>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    // TODO: Test
    if category_data.encrypted_blob.len() > env::CONF.max_small_object_size {
        return Err(HttpErrorResponse::InputTooLarge(String::from(
            "Encrypted blob too large",
        )));
    }

    let category_id = (&category_data.category_id).try_into()?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_category(
            category_id,
            &category_data.encrypted_blob,
            category_data.version_nonce,
            category_data.expected_previous_version_nonce,
            budget_access_token.0.claims.budget_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDate => {
                return Err(HttpErrorResponse::OutOfDate(String::from(
                    "Out of date version nonce",
                )));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("Category not found"),
                    DoesNotExistType::Category,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to update category",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_id: ProtoBuf<CategoryId>,
) -> Result<HttpResponse, HttpErrorResponse> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let category_id = (&category_id.value).try_into()?;

    match web::block(move || {
        let budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_category(category_id, budget_access_token.0.claims.budget_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("Category not found"),
                    DoesNotExistType::Category,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to delete category",
                )));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

async fn obtain_public_key(
    key_id: Uuid,
    budget_id: Uuid,
    db_thread_pool: &DbThreadPool,
) -> Result<BudgetAccessKey, HttpErrorResponse> {
    let budget_dao = db::budget::Dao::new(db_thread_pool);
    let key = match web::block(move || budget_dao.get_public_budget_key(key_id, budget_id)).await? {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("No budget with ID matching token"),
                    DoesNotExistType::Budget,
                ));
            }
            _ => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to get public budget access key",
                )));
            }
        },
    };

    Ok(key)
}

async fn verify_read_write_access<F: TokenLocation>(
    budget_access_token: &SpecialAccessToken<BudgetAccessToken, F>,
    db_thread_pool: &DbThreadPool,
) -> Result<(), HttpErrorResponse> {
    let claims = &budget_access_token.0.claims;
    let public_key = obtain_public_key(claims.key_id, claims.budget_id, db_thread_pool).await?;
    budget_access_token.0.verify(&public_key.public_key)?;

    if public_key.read_only {
        return Err(HttpErrorResponse::ReadOnlyAccess(String::from(
            "User has read-only access to budget",
        )));
    }

    Ok(())
}

async fn verify_read_access<F: TokenLocation>(
    budget_access_token: &SpecialAccessToken<BudgetAccessToken, F>,
    db_thread_pool: &DbThreadPool,
) -> Result<(), HttpErrorResponse> {
    let claims = &budget_access_token.0.claims;
    let public_key = obtain_public_key(claims.key_id, claims.budget_id, db_thread_pool).await?;
    budget_access_token.0.verify(&public_key.public_key)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use super::*;

    use entries_common::messages::{
        Budget as BudgetMessage, BudgetIdAndEncryptionKey, BudgetList, BudgetShareInviteList,
        EntryIdAndCategoryId, ErrorType, InvitationId, ServerErrorResponse, UuidV4,
    };
    use entries_common::messages::{BudgetFrame, CategoryWithTempId};
    use entries_common::models::budget::Budget;
    use entries_common::schema::budget_access_keys as budget_access_key_fields;
    use entries_common::schema::budget_access_keys::dsl::budget_access_keys;
    use entries_common::schema::budgets::dsl::budgets;
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
    use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
    use ed25519_dalek as ed25519;
    use ed25519_dalek::Signer;
    use entries_common::token::budget_accept_token::BudgetAcceptTokenClaims;
    use entries_common::token::budget_invite_sender_token::BudgetInviteSenderTokenClaims;
    use prost::Message;
    use rand::Rng;

    use crate::env;
    use crate::handlers::test_utils::{self, gen_budget_token, gen_bytes};
    use crate::services::api::RouteLimiters;

    #[actix_rt::test]
    async fn test_create_and_get_budget_and_entry_and_category() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_budget = NewBudget {
            encrypted_blob: gen_bytes(32),
            version_nonce: rand::thread_rng().gen(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: rand::thread_rng().gen(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: rand::thread_rng().gen(),
                },
            ],
            user_public_budget_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let mut budget_data = BudgetFrame::decode(resp_body).unwrap();
        budget_data
            .category_ids
            .sort_unstable_by(|a, b| a.temp_id.cmp(&b.temp_id));

        let budget = budgets
            .find(Uuid::try_from(budget_data.id).unwrap())
            .get_result::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let budget_access_token = gen_budget_token(
            budget.id,
            budget_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_ids = budget_data
            .category_ids
            .into_iter()
            .map(|c| Uuid::try_from(c.real_id).unwrap())
            .collect::<Vec<_>>();

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 2);

        let categories_iter = budget_message
            .categories
            .iter()
            .zip(new_budget.categories.iter());

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

        assert_eq!(budget_message.entries.len(), 0);

        let new_category = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
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

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 3);

        for category in budget_message.categories.iter() {
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

        assert_eq!(budget_message.entries.len(), 0);

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            category_id: Some(new_category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
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

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 3);

        for category in budget_message.categories.iter() {
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

        assert_eq!(budget_message.entries.len(), 1);

        assert_eq!(
            Uuid::try_from(&budget_message.entries[0].id).unwrap(),
            new_entry_id,
        );
        assert_eq!(
            Uuid::try_from(budget_message.entries[0].category_id.clone().unwrap()).unwrap(),
            new_category_id,
        );
        assert_eq!(
            budget_message.entries[0].encrypted_blob,
            new_entry.encrypted_blob,
        );
        assert_eq!(
            budget_message.entries[0].version_nonce,
            new_entry.version_nonce,
        );

        let new_entry2 = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            category_id: None,
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
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

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(budget_message.entries.len(), 2);

        let first_entry = budget_message
            .entries
            .iter()
            .find(|e| Uuid::try_from(&e.id).unwrap() == new_entry_id)
            .unwrap();
        let second_entry = budget_message
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
            entry_version_nonce: rand::thread_rng().gen(),
            category_encrypted_blob: gen_bytes(12),
            category_version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_and_category_ids = EntryIdAndCategoryId::decode(resp_body).unwrap();

        let new_entry3_id: Uuid = new_entry_and_category_ids.entry_id.try_into().unwrap();
        let new_category4_id: Uuid = new_entry_and_category_ids.category_id.try_into().unwrap();

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 4);
        assert_eq!(budget_message.entries.len(), 3);

        let new_category4 = budget_message
            .categories
            .iter()
            .find(|c| Uuid::try_from(&c.id).unwrap() == new_category4_id)
            .unwrap();

        let new_entry3 = budget_message
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
    async fn test_create_budget_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let new_budget = NewBudget {
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: rand::thread_rng().gen(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: rand::thread_rng().gen(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: rand::thread_rng().gen(),
                },
            ],
            user_public_budget_key: gen_bytes(40),
        };

        let req = TestRequest::post()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let new_budget = NewBudget {
            encrypted_blob: gen_bytes(32),
            version_nonce: rand::thread_rng().gen(),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                    version_nonce: rand::thread_rng().gen(),
                },
                CategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                    version_nonce: rand::thread_rng().gen(),
                },
            ],
            user_public_budget_key: vec![0; env::CONF.max_encryption_key_size + 1],
        };

        let req = TestRequest::post()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);
    }

    #[actix_rt::test]
    async fn test_get_multiple_budgets() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (budget1, budget1_token) = test_utils::create_budget(&access_token).await;
        let (budget2, budget2_token) = test_utils::create_budget(&access_token).await;
        let (budget3, budget3_token) = test_utils::create_budget(&access_token).await;

        let new_entry_and_category = EntryAndCategory {
            entry_encrypted_blob: gen_bytes(30),
            entry_version_nonce: rand::thread_rng().gen(),
            category_encrypted_blob: gen_bytes(12),
            category_version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry_and_category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget3_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry_and_category.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let new_entry_and_category_ids = EntryIdAndCategoryId::decode(resp_body).unwrap();

        let new_entry_id: Uuid = new_entry_and_category_ids.entry_id.try_into().unwrap();
        let new_category_id: Uuid = new_entry_and_category_ids.category_id.try_into().unwrap();

        let budget_access_tokens = BudgetAccessTokenList {
            tokens: vec![budget1_token, budget2_token, budget3_token],
        };

        let req = TestRequest::get()
            .uri("/api/budget/multiple")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(budget_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_list = BudgetList::decode(resp_body).unwrap();

        let resp_budget1 = budget_list
            .budgets
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == budget1.id)
            .unwrap();
        let resp_budget2 = budget_list
            .budgets
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == budget2.id)
            .unwrap();
        let resp_budget3 = budget_list
            .budgets
            .iter()
            .find(|b| Uuid::try_from(&b.id).unwrap() == budget3.id)
            .unwrap();

        assert_eq!(budget_list.budgets.len(), 3);

        assert_eq!(Uuid::try_from(resp_budget1.id.clone()).unwrap(), budget1.id);
        assert_eq!(resp_budget1.encrypted_blob, budget1.encrypted_blob);
        assert_eq!(resp_budget1.version_nonce, budget1.version_nonce);
        assert_eq!(resp_budget1.categories.len(), 0);
        assert_eq!(resp_budget1.entries.len(), 0);

        assert_eq!(Uuid::try_from(resp_budget2.id.clone()).unwrap(), budget2.id);
        assert_eq!(resp_budget2.encrypted_blob, budget2.encrypted_blob);
        assert_eq!(resp_budget2.version_nonce, budget2.version_nonce);
        assert_eq!(resp_budget2.categories.len(), 0);
        assert_eq!(resp_budget2.entries.len(), 0);

        assert_eq!(Uuid::try_from(resp_budget3.id.clone()).unwrap(), budget3.id);
        assert_eq!(resp_budget3.encrypted_blob, budget3.encrypted_blob);
        assert_eq!(resp_budget3.version_nonce, budget3.version_nonce);
        assert_eq!(resp_budget3.categories.len(), 1);
        assert_eq!(resp_budget3.entries.len(), 1);

        assert_eq!(
            Uuid::try_from(&resp_budget3.categories[0].id).unwrap(),
            new_category_id
        );
        assert_eq!(
            Uuid::try_from(&resp_budget3.categories[0].budget_id).unwrap(),
            budget3.id
        );
        assert_eq!(
            resp_budget3.categories[0].encrypted_blob,
            new_entry_and_category.category_encrypted_blob
        );
        assert_eq!(
            resp_budget3.categories[0].version_nonce,
            new_entry_and_category.category_version_nonce
        );

        assert_eq!(
            Uuid::try_from(&resp_budget3.entries[0].id).unwrap(),
            new_entry_id
        );
        assert_eq!(
            Uuid::try_from(&resp_budget3.entries[0].budget_id).unwrap(),
            budget3.id
        );
        assert_eq!(
            Uuid::try_from(resp_budget3.entries[0].category_id.as_ref().unwrap()).unwrap(),
            new_category_id
        );
        assert_eq!(
            resp_budget3.entries[0].encrypted_blob,
            new_entry_and_category.entry_encrypted_blob
        );
        assert_eq!(
            resp_budget3.entries[0].version_nonce,
            new_entry_and_category.entry_version_nonce
        );

        let mut tokens = Vec::with_capacity(101);
        for i in 0..101 {
            tokens.push(format!("faketoken{}", i));
        }
        let budget_access_tokens = BudgetAccessTokenList { tokens };

        let req = TestRequest::get()
            .uri("/api/budget/multiple")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(budget_access_tokens.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_err = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_err.err_type, ErrorType::TooManyRequested as i32);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_get_multiple_budgets_fails_with_too_many_tokens() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let budget_access_tokens = BudgetAccessTokenList {
            tokens: vec![String::from("test"); env::CONF.max_budget_fetch_count + 1],
        };

        let req = TestRequest::get()
            .uri("/api/budget/multiple")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(budget_access_tokens.encode_to_vec())
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
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = Vec::from(key_pair.verifying_key().to_bytes());

        let new_budget = NewBudget {
            encrypted_blob: gen_bytes(32),
            version_nonce: rand::thread_rng().gen(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: rand::thread_rng().gen(),
            }],
            user_public_budget_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_data = BudgetFrame::decode(resp_body).unwrap();

        let budget = budgets
            .find(Uuid::try_from(budget_data.id).unwrap())
            .get_result::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let budget_access_token = gen_budget_token(
            budget.id,
            budget_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_id: Uuid = (&budget_data.category_ids[0].real_id).try_into().unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);

        assert_eq!(budget_message.categories.len(), 1);

        let category_message = &budget_message.categories[0];

        assert_eq!(Uuid::try_from(&category_message.id).unwrap(), category_id,);
        assert_eq!(
            category_message.encrypted_blob,
            new_budget.categories[0].encrypted_blob
        );

        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category_id,
        );

        let category_id_message = CategoryId {
            value: category_id.into(),
        };

        let req = TestRequest::delete()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_id_message.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);

        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert!(entry_message.category_id.is_none());
    }

    #[actix_rt::test]
    async fn test_delete_entry() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;

        let key_pair = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = key_pair.verifying_key().to_bytes().to_vec();

        let new_budget = NewBudget {
            encrypted_blob: gen_bytes(32),
            version_nonce: rand::thread_rng().gen(),
            categories: vec![CategoryWithTempId {
                temp_id: 0,
                encrypted_blob: gen_bytes(40),
                version_nonce: rand::thread_rng().gen(),
            }],
            user_public_budget_key: public_key,
        };

        let req = TestRequest::post()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_data = BudgetFrame::decode(resp_body).unwrap();

        let budget = budgets
            .find(Uuid::try_from(budget_data.id).unwrap())
            .get_result::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let budget_access_token = gen_budget_token(
            budget.id,
            budget_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        let category_id: Uuid = (&budget_data.category_ids[0].real_id).try_into().unwrap();

        let new_entry = EncryptedBlobAndCategoryId {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            category_id: Some(category_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);

        assert_eq!(budget_message.categories.len(), 1);
        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

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
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_id_message.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);

        assert_eq!(budget_message.categories.len(), 1);
        assert_eq!(budget_message.entries.len(), 0);
    }

    #[actix_rt::test]
    async fn test_edit_budget() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (budget, budget_token) = test_utils::create_budget(&access_token).await;

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: budget.version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: budget.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, blob_update.encrypted_blob);
        assert_eq!(budget_message.version_nonce, blob_update.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_edit_budget_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (budget, budget_token) = test_utils::create_budget(&access_token).await;

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: vec![0; env::CONF.max_small_object_size + 1],
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: budget.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (budget, budget_token) = test_utils::create_budget(&access_token).await;

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);

        let new_category1 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            category_id: Some(category2_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 2);
        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: expected_previous_version_nonce.wrapping_sub(1),
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let entry_update = EntryUpdate {
            entry_id: Uuid::new_v4().into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce,
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce,
            category_id: Some(Uuid::new_v4().into()),
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce,
            category_id: Some(category1_id.into()),
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        expected_previous_version_nonce = entry_update.version_nonce;

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.categories.len(), 2);
        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, entry_update.encrypted_blob);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category1_id,
        );

        let entry_update = EntryUpdate {
            entry_id: entry_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: expected_previous_version_nonce.wrapping_add(1),
            category_id: None,
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce,
            category_id: None,
        };

        let req = TestRequest::put()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(entry_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.categories.len(), 2);
        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, entry_update.encrypted_blob);
        assert!(entry_message.category_id.is_none());
    }

    #[actix_rt::test]
    async fn test_edit_category() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, access_token, _, _) = test_utils::create_user().await;
        let (budget, budget_token) = test_utils::create_budget(&access_token).await;

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);

        let new_category1 = NewEncryptedBlob {
            value: gen_bytes(40),
            version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
        };

        let req = TestRequest::post()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            category_id: Some(category2_id.into()),
        };

        let req = TestRequest::post()
            .uri("/api/budget/entry")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_entry.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 2);

        let cat1_pos = budget_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(budget_message.categories[cat1_pos].id, category1_id.into());
        assert_eq!(
            budget_message.categories[cat1_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            budget_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(budget_message.categories[cat2_pos].id, category2_id.into());
        assert_eq!(
            budget_message.categories[cat2_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat2_pos].encrypted_blob,
            new_category2.value
        );
        assert_eq!(
            budget_message.categories[cat2_pos].version_nonce,
            new_category2.version_nonce
        );

        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );

        let category_update = CategoryUpdate {
            category_id: category2_id.into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: new_category2.version_nonce.wrapping_add(1),
        };

        let req = TestRequest::put()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let error_message = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(error_message.err_type, ErrorType::OutOfDate as i32);

        let category_update = CategoryUpdate {
            category_id: Uuid::new_v4().into(),
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: new_category2.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: new_category2.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 2);

        let cat1_pos = budget_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(budget_message.categories[cat1_pos].id, category1_id.into());
        assert_eq!(
            budget_message.categories[cat1_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            budget_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(budget_message.categories[cat2_pos].id, category2_id.into());
        assert_eq!(
            budget_message.categories[cat2_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat2_pos].encrypted_blob,
            category_update.encrypted_blob
        );
        assert_eq!(
            budget_message.categories[cat2_pos].version_nonce,
            category_update.version_nonce
        );

        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: category_update_version_nonce.wrapping_sub(1),
        };

        let req = TestRequest::put()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
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
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: category_update_version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget/category")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(category_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", access_token.as_str()))
            .insert_header(("BudgetAccessToken", budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);

        assert_eq!(budget_message.categories.len(), 2);

        let cat1_pos = budget_message
            .categories
            .iter()
            .position(|c| c.id == category1_id.into())
            .unwrap();
        let cat2_pos = if cat1_pos == 0 { 1 } else { 0 };

        assert_eq!(budget_message.categories[cat1_pos].id, category1_id.into());
        assert_eq!(
            budget_message.categories[cat1_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat1_pos].encrypted_blob,
            new_category1.value
        );
        assert_eq!(
            budget_message.categories[cat1_pos].version_nonce,
            new_category1.version_nonce
        );

        assert_eq!(budget_message.categories[cat2_pos].id, category2_id.into());
        assert_eq!(
            budget_message.categories[cat2_pos].budget_id,
            budget.id.into()
        );
        assert_eq!(
            budget_message.categories[cat2_pos].encrypted_blob,
            category_update.encrypted_blob
        );
        assert_eq!(
            budget_message.categories[cat2_pos].version_nonce,
            category_update.version_nonce
        );

        assert_eq!(budget_message.entries.len(), 1);

        let entry_message = &budget_message.entries[0];

        assert_eq!(entry_message.encrypted_blob, new_entry.encrypted_blob);
        assert_eq!(entry_message.version_nonce, new_entry.version_nonce);
        assert_eq!(
            Uuid::try_from(entry_message.category_id.clone().unwrap()).unwrap(),
            category2_id,
        );
    }

    #[actix_rt::test]
    async fn test_invite_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id);

        let (budget, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;
        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("BudgetAccessToken", sender_budget_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        assert_eq!(invites.len(), 1);
        assert_eq!(
            recipient.public_key_id,
            <&UuidV4 as TryInto<Uuid>>::try_into(
                &invites[0].recipient_public_key_id_used_by_sender
            )
            .unwrap()
        );
        assert_eq!(
            recipient.public_key_id,
            <&UuidV4 as TryInto<Uuid>>::try_into(
                &invites[0].recipient_public_key_id_used_by_server
            )
            .unwrap()
        );

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = BudgetAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            budget_id: budget.id,
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

        let access_private_key = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
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
            .uri("/api/budget/invitation/accept")
            .insert_header(("BudgetAcceptToken", bad_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::put()
            .uri("/api/budget/invitation/accept")
            .insert_header(("BudgetAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let message = BudgetIdAndEncryptionKey::decode(resp_body).unwrap();

        assert_eq!(message.budget_id, budget.id.into());
        assert_eq!(
            message.encryption_key_encrypted,
            invite_info.encryption_key_encrypted
        );
        assert_eq!(message.read_only, invite_info.read_only);

        let access_key_id = Uuid::try_from(message.budget_access_key_id).unwrap();
        let recipient_budget_token =
            gen_budget_token(budget.id, access_key_id, &access_private_key);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", &recipient_budget_token[..10]))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(&budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, budget.encrypted_blob);
        assert_eq!(budget_message.version_nonce, budget.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);

        let blob_update = EncryptedBlobUpdate {
            encrypted_blob: gen_bytes(20),
            version_nonce: rand::thread_rng().gen(),
            expected_previous_version_nonce: budget.version_nonce,
        };

        let req = TestRequest::put()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        diesel::update(budget_access_keys.find((access_key_id, budget.id)))
            .set(budget_access_key_fields::read_only.eq(false))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let req = TestRequest::put()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(blob_update.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_message = BudgetMessage::decode(resp_body).unwrap();

        assert_eq!(Uuid::try_from(budget_message.id).unwrap(), budget.id);
        assert_eq!(budget_message.encrypted_blob, blob_update.encrypted_blob);
        assert_eq!(budget_message.version_nonce, blob_update.version_nonce);
        assert_eq!(budget_message.categories.len(), 0);
        assert_eq!(budget_message.entries.len(), 0);
        assert_eq!(budget_message.version_nonce, blob_update.version_nonce);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_invite_user_fails_with_large_input() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, _, _, _) = test_utils::create_user().await;
        let (_, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: vec![0; env::CONF.max_encryption_key_size + 1],
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("BudgetAccessToken", sender_budget_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: vec![0; env::CONF.max_encryption_key_size + 1],
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("BudgetAccessToken", sender_budget_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("BudgetAccessToken", sender_budget_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("BudgetAccessToken", sender_budget_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email.clone(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: vec![0; env::CONF.max_small_object_size + 1],
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.clone()))
            .insert_header(("BudgetAccessToken", sender_budget_token.clone()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let resp_body = ServerErrorResponse::decode(resp_body).unwrap();

        assert_eq!(resp_body.err_type, ErrorType::InputTooLarge as i32);

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: vec![0; env::CONF.max_encryption_key_size + 1],
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("BudgetAccessToken", sender_budget_token))
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
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, _, _, _) = test_utils::create_user().await;
        let (_, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;

        let invite_info = UserInvitationToBudget {
            recipient_user_email: "invalid_email_address".to_string(),
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(20),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("BudgetAccessToken", sender_budget_token))
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
    async fn test_retract_invitation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;
        let (_, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;

        let recipient_keypair = Rsa::generate(512).unwrap();
        let recipient_public_key = recipient_keypair.public_key_to_der().unwrap();

        diesel::update(users.find(recipient.id))
            .set(user_fields::public_key.eq(recipient_public_key.to_vec()))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let invite_sender_keypair = ed25519::SigningKey::generate(&mut OsRng);
        let invite_sender_pub_key = invite_sender_keypair.verifying_key().to_bytes();

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: invite_sender_pub_key.to_vec(),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(60))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invite_id = InvitationId::decode(resp_body).unwrap();

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        assert_eq!(invites.len(), 1);

        let claims = BudgetInviteSenderTokenClaims {
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
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::delete()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetInviteSenderToken", sender_budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::delete()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetInviteSenderToken", invite_sender_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        assert!(invites.is_empty());
    }

    #[actix_rt::test]
    async fn test_decline_invitation() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id);
        let (budget, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("BudgetAccessToken", sender_budget_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = BudgetAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            budget_id: budget.id,
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

        let access_private_key = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
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
            .uri("/api/budget/invitation/decline")
            .insert_header(("BudgetAcceptToken", bad_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = TestRequest::put()
            .uri("/api/budget/invitation/decline")
            .insert_header(("BudgetAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        assert!(invites.is_empty());
    }

    #[actix_rt::test]
    async fn test_leave_budget() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let (_, sender_access_token, _, _) = test_utils::create_user().await;
        let (recipient, recipient_access_token, _, _) = test_utils::create_user().await;

        let recipient_private_key = test_utils::gen_new_user_rsa_key(recipient.id);

        let (budget, sender_budget_token) = test_utils::create_budget(&sender_access_token).await;

        let invite_info = UserInvitationToBudget {
            recipient_user_email: recipient.email,
            recipient_public_key_id_used_by_sender: recipient.public_key_id.into(),
            recipient_public_key_id_used_by_server: recipient.public_key_id.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only: true,
        };

        let req = TestRequest::post()
            .uri("/api/budget/invitation")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].budget_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = BudgetAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            budget_id: budget.id,
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

        let access_private_key = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
        let access_public_key = Vec::from(access_private_key.verifying_key().to_bytes());
        let access_public_key = PublicKey {
            value: access_public_key,
        };

        let req = TestRequest::put()
            .uri("/api/budget/invitation/accept")
            .insert_header(("BudgetAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let message = BudgetIdAndEncryptionKey::decode(resp_body).unwrap();

        assert_eq!(message.budget_id, budget.id.into());
        assert_eq!(
            message.encryption_key_encrypted,
            invite_info.encryption_key_encrypted
        );
        assert_eq!(message.read_only, invite_info.read_only);

        let access_key_id = Uuid::try_from(message.budget_access_key_id).unwrap();
        let recipient_budget_token =
            gen_budget_token(budget.id, access_key_id, &access_private_key);

        // Check both sender and recipient can access the budget
        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let budget_access_key_count = budget_access_keys
            .filter(budget_access_key_fields::budget_id.eq(budget.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(budget_access_key_count, 2);

        let req = TestRequest::delete()
            .uri("/api/budget/leave")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let budget_access_key_count = budget_access_keys
            .filter(budget_access_key_fields::budget_id.eq(budget.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(budget_access_key_count, 1);

        // Check recipient can access the budget but sender no longer has access
        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        assert!(budgets
            .find(budget.id)
            .first::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .is_ok());

        let req = TestRequest::delete()
            .uri("/api/budget/leave")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let budget_access_key_count = budget_access_keys
            .filter(budget_access_key_fields::budget_id.eq(budget.id))
            .count()
            .get_result::<i64>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        assert_eq!(budget_access_key_count, 0);

        // Check both sender and recipient no longer have access to the budget
        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", sender_access_token.as_str()))
            .insert_header(("BudgetAccessToken", sender_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::get()
            .uri("/api/budget")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("BudgetAccessToken", recipient_budget_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        assert!(budgets
            .find(budget.id)
            .first::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .is_err());
    }
}
