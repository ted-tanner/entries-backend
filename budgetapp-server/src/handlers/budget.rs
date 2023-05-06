use budgetapp_utils::models::budget_access_key::BudgetAccessKey;
use budgetapp_utils::request_io::{
    InputBudget, InputBudgetAccessTokenList, InputCategoryId, InputEditBudget, InputEditCategory,
    InputEditEntry, InputEncryptedBlob, InputEntryAndCategory, InputEntryId, InputPublicKey,
    OutputBudgetShareInviteWithoutKey, OutputCategoryId, OutputEntryId, UserInvitationToBudget,
};
use budgetapp_utils::token::budget_accept_token::BudgetAcceptToken;
use budgetapp_utils::token::budget_access_token::BudgetAccessToken;
use budgetapp_utils::token::budget_invite_sender_token::BudgetInviteSenderToken;
use budgetapp_utils::token::Token;
use budgetapp_utils::{db, db::DaoError, db::DbThreadPool};

use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;

use crate::handlers::error::ServerError;
use crate::middleware::auth::{Access, VerifiedToken};
use crate::middleware::special_access_token::SpecialAccessToken;
use crate::middleware::{FromHeader, TokenLocation};

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    verify_read_access(&budget_access_token, &db_thread_pool).await?;

    let budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_budget(budget_access_token.0.budget_id())
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get budget data",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budget))
}

pub async fn get_multiple(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_tokens: web::Json<InputBudgetAccessTokenList>,
) -> Result<HttpResponse, ServerError> {
    const INVALID_ID_MSG: &str = "One of the provided budget access tokens had an invalid ID";
    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut budget_ids = Vec::new();

    for token in budget_access_tokens.budget_access_tokens.iter() {
        let token = match BudgetAccessToken::from_str(token) {
            Ok(t) => t,
            Err(_) => {
                return Err(ServerError::InvalidFormat(Some(String::from(
                    INVALID_ID_MSG,
                ))))
            }
        };

        key_ids.push(token.key_id());
        budget_ids.push(token.budget_id());
        tokens.insert(token.key_id(), token);
    }

    let budget_ids = Arc::new(budget_ids);
    let budget_ids_ref = Arc::clone(&budget_ids);

    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let public_keys = match web::block(move || {
        budget_dao.get_multiple_public_budget_keys(&key_ids, &budget_ids_ref)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get budget data",
                ))));
            }
        },
    };

    if public_keys.len() != tokens.len() {
        return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG))));
    }

    for key in public_keys {
        let token = match tokens.get(&key.key_id) {
            Some(t) => t,
            None => return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG)))),
        };

        if !token.verify(key.public_key.as_bytes()) {
            return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG))));
        }
    }

    let budgets = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_multiple_budgets_by_id(&budget_ids)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "One of the provided IDs did not match a budget",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get budget data",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budgets))
}

pub async fn create(
    db_thread_pool: web::Data<DbThreadPool>,
    budget_data: web::Json<InputBudget>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let new_budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_budget(budget_data.0)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("{e}");
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to create budget",
            ))));
        }
    };

    Ok(HttpResponse::Created().json(new_budget))
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    budget_data: web::Json<InputEditBudget>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_budget(
            budget_access_token.0.budget_id(),
            &budget_data.encrypted_blob,
            &budget_data.expected_previous_data_hash,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Out of date hash",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to edit budget",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn invite_user(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    invitation_info: web::Json<UserInvitationToBudget>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let _inviting_user_id = user_access_token.0.user_id;

    if invitation_info.recipient_user_email == user_access_token.0.user_email {
        return Err(ServerError::InputRejected(Some(String::from(
            "Inviter and recipient are the same",
        ))));
    }

    let invite_and_accept_key_ids = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.invite_user(
            &invitation_info.recipient_user_email,
            &invitation_info.sender_public_key,
            &invitation_info.encryption_key_encrypted,
            &invitation_info.budget_accept_private_key_encrypted,
            &invitation_info.budget_info_encrypted,
            &invitation_info.sender_info_encrypted,
            &invitation_info.budget_accept_private_key_info_encrypted,
            &invitation_info.share_info_symmetric_key_encrypted,
            budget_access_token.0.budget_id(),
            &invitation_info.budget_share_public_key,
            invitation_info.expiration,
            invitation_info.read_only,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget or invite with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to share budget",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invite_and_accept_key_ids))
}

pub async fn retract_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    invite_sender_token: SpecialAccessToken<BudgetInviteSenderToken, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let invitation_id = invite_sender_token.0.invitation_id();

    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let invite_sender_public_key =
        match web::block(move || budget_dao.get_budget_invite_sender_public_key(invitation_id))
            .await?
        {
            Ok(k) => k,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(ServerError::NotFound(Some(String::from(
                        "No invitation with ID matching token",
                    ))));
                }
                _ => {
                    log::error!("{e}");
                    return Err(ServerError::DatabaseTransactionError(Some(String::from(
                        "Failed to get public budget access key",
                    ))));
                }
            },
        };

    if !invite_sender_token
        .0
        .verify(invite_sender_public_key.as_bytes())
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No invite with ID matching token",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invite_sender_token.0.invitation_id())
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete invitation",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn accept_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<BudgetAcceptToken, FromHeader>,
    budget_user_public_key: web::Json<InputPublicKey>,
) -> Result<HttpResponse, ServerError> {
    let key_id = accept_token.0.key_id();
    let budget_id = accept_token.0.budget_id();

    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let budget_accept_key =
        match web::block(move || budget_dao.get_budget_accept_public_key(key_id, budget_id)).await?
        {
            Ok(key) => key,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(ServerError::NotFound(Some(String::from(
                        "No share invite with ID matching token",
                    ))));
                }
                _ => {
                    log::error!("{e}");
                    return Err(ServerError::DatabaseTransactionError(Some(String::from(
                        "Failed to accept invitation",
                    ))));
                }
            },
        };

    if budget_accept_key.expiration < SystemTime::now() {
        return Err(ServerError::NotFound(Some(String::from(
            "Invitation has expired",
        ))));
    }

    if !accept_token
        .0
        .verify(budget_accept_key.public_key.as_bytes())
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No invite with ID matching token",
        ))));
    }

    let budget_keys = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.accept_invitation(
            budget_accept_key.key_id,
            budget_accept_key.budget_id,
            budget_accept_key.read_only,
            accept_token.0.claims().invitation_id,
            &user_access_token.0.user_email,
            &budget_user_public_key.0.public_key,
        )
    })
    .await?
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to accept invitation",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budget_keys))
}

pub async fn decline_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    accept_token: SpecialAccessToken<BudgetAcceptToken, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let key_id = accept_token.0.key_id();
    let budget_id = accept_token.0.budget_id();

    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let budget_accept_key =
        match web::block(move || budget_dao.get_budget_accept_public_key(key_id, budget_id)).await?
        {
            Ok(key) => key,
            Err(e) => match e {
                DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                    return Err(ServerError::NotFound(Some(String::from(
                        "No share invite with ID matching token",
                    ))));
                }
                _ => {
                    log::error!("{e}");
                    return Err(ServerError::DatabaseTransactionError(Some(String::from(
                        "Failed to decline invitation",
                    ))));
                }
            },
        };

    if !accept_token
        .0
        .verify(budget_accept_key.public_key.as_bytes())
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No invite with ID matching token",
        ))));
    }

    let accept_token_claims = accept_token.0.claims();

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.reject_invitation(
            accept_token_claims.invitation_id,
            accept_token_claims.key_id,
            &user_access_token.0.user_email,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to decline invitation",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn get_all_pending_invitations_for_user(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    let invites = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_pending_invitations_for_user(&user_access_token.0.user_email)
    })
    .await?
    {
        Ok(invites) => invites,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputBudgetShareInviteWithoutKey>::new()));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find invitations",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invites))
}

pub async fn leave_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
) -> Result<HttpResponse, ServerError> {
    verify_read_access(&budget_access_token, &db_thread_pool).await?;

    let claims = budget_access_token.0.claims();

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.leave_budget(claims.budget_id, claims.key_id)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "User budget association not found",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to remove association with budget",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_data: web::Json<InputEncryptedBlob>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let entry_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry(
            &entry_data.0.encrypted_blob,
            budget_access_token.0.budget_id(),
        )
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(OutputEntryId { entry_id }))
}

pub async fn create_entry_and_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_and_category_data: web::Json<InputEntryAndCategory>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let entry_and_category_ids = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao
            .create_entry_and_category(entry_and_category_data.0, budget_access_token.0.budget_id())
    })
    .await?
    {
        Ok(ids) => ids,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(entry_and_category_ids))
}

pub async fn edit_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_data: web::Json<InputEditEntry>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_entry(
            entry_data.0.entry_id,
            &entry_data.encrypted_blob,
            &entry_data.expected_previous_data_hash,
            budget_access_token.0.budget_id(),
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Out of date hash",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No entry with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    entry_id: web::Query<InputEntryId>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_entry(entry_id.0.entry_id, budget_access_token.0.budget_id())
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No entry with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn create_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_data: web::Json<InputEncryptedBlob>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    let category_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_category(
            &category_data.0.encrypted_blob,
            budget_access_token.0.budget_id(),
        )
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(OutputCategoryId { category_id }))
}

pub async fn edit_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_data: web::Json<InputEditCategory>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_category(
            category_data.category_id,
            &category_data.encrypted_blob,
            &category_data.expected_previous_data_hash,
            budget_access_token.0.budget_id(),
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::OutOfDateHash => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Out of date hash",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No category with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_category(
    db_thread_pool: web::Data<DbThreadPool>,
    _user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: SpecialAccessToken<BudgetAccessToken, FromHeader>,
    category_id: web::Query<InputCategoryId>,
) -> Result<HttpResponse, ServerError> {
    verify_read_write_access(&budget_access_token, &db_thread_pool).await?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_category(category_id.0.category_id, budget_access_token.0.budget_id())
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No category with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

async fn obtain_public_key(
    key_id: Uuid,
    budget_id: Uuid,
    db_thread_pool: &DbThreadPool,
) -> Result<BudgetAccessKey, ServerError> {
    let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
    let key = match web::block(move || budget_dao.get_public_budget_key(key_id, budget_id)).await? {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with ID matching token",
                ))));
            }
            _ => {
                log::error!("{e}");
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get public budget access key",
                ))));
            }
        },
    };

    Ok(key)
}

async fn verify_read_write_access<F: TokenLocation>(
    budget_access_token: &SpecialAccessToken<BudgetAccessToken, F>,
    db_thread_pool: &DbThreadPool,
) -> Result<(), ServerError> {
    let budget_id = budget_access_token.0.budget_id();
    let key_id = budget_access_token.0.key_id();
    let public_key = obtain_public_key(key_id, budget_id, &db_thread_pool).await?;

    if !budget_access_token
        .0
        .verify(public_key.public_key.as_bytes())
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No budget with ID matching token",
        ))));
    }

    if public_key.read_only == true {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "User has read-only access to budget",
        ))));
    }

    Ok(())
}

async fn verify_read_access<F: TokenLocation>(
    budget_access_token: &SpecialAccessToken<BudgetAccessToken, F>,
    db_thread_pool: &DbThreadPool,
) -> Result<(), ServerError> {
    let budget_id = budget_access_token.0.budget_id();
    let key_id = budget_access_token.0.key_id();
    let public_key = obtain_public_key(key_id, budget_id, &db_thread_pool).await?;

    if !budget_access_token
        .0
        .verify(public_key.public_key.as_bytes())
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No budget with ID matching token",
        ))));
    }

    Ok(())
}
