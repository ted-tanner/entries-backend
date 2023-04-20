use budgetapp_utils::models::budget_access_key::BudgetAccessKey;
use budgetapp_utils::request_io::{
    InputBudget, InputBudgetAccessTokenList, InputBudgetId, InputCategoryId, InputEditBudget,
    InputEditCategory, InputEditEntry, InputEncryptedBlob, InputEntryAndCategory, InputEntryId,
    InputShareInviteId, OutputBudgetShareInviteWithoutKey, OutputCategoryId, OutputEntryId,
    UserInvitationToBudget,
};
use budgetapp_utils::token::Token;
use budgetapp_utils::{db, db::DaoError, db::DbThreadPool};

use actix_web::{web, HttpResponse};
use std::collections::HashMap;
use std::sync::Arc;

use crate::handlers::error::ServerError;
use crate::middleware::auth::{Access, FromHeader, VerifiedToken};
use crate::middleware::budget_access_token_header::BudgetAccessToken;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: BudgetAccessToken,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let budget_id = budget_access_token.claims.budget_id;
    let key_id = budget_access_token.claims.key_id;
    let public_key = obtain_public_key(key_id, budget_id, &db_thread_pool).await?;

    if !budget_access_token
        .0
        .verify_for_user(user_access_token.0.user_id, &public_key)
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No budget with provided ID",
        ))));
    }

    let budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_budget(budget_id)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
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
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_tokens: web::Json<InputBudgetAccessTokenList>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    const INVALID_ID_MSG: &str = "One of the provided budget access tokens had an invalid ID";
    let mut tokens = HashMap::new();
    let mut key_ids = Vec::new();
    let mut budget_ids = Vec::new();

    for token in budget_access_tokens.budget_access_tokens.iter() {
        let token = match BudgetToken::from_str(token) {
            Ok(t) => t,
            Err(_) => {
                return Err(ServerError::InvalidFormat(Some(String::from(
                    "One of the provided budget access tokens was invalid",
                ))))
            }
        };

        key_ids.push(token.key_id);
        budget_ids.push(token.budget_id);
        tokens.insert(token.key_id, token);
    }

    let budget_ids = Arc::new(budget_ids);
    let budget_ids_ref = Arc::clone(&budget_ids);

    let db_thread_pool_ref = db_thread_pool.clone();
    let public_keys = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_ref);
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
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get budget data",
                ))));
            }
        },
    };

    if public_keys.len() != tokens.len() {
        return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG))));
    }

    for (key_id, public_key) in public_keys {
        let token = match tokens.get(&key_id) {
            Some(t) => t,
            None => return Err(ServerError::NotFound(Some(String::from(INVALID_ID_MSG)))),
        };

        if !token.verify_for_user(user_access_token.user_id, &public_key) {
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
                log::error!("{}", e);
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
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_data: web::Json<InputBudget>,
) -> Result<HttpResponse, ServerError> {
    // Return an error if user is unverified
    let _ = user_access_token.0?;

    let new_budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_budget(budget_data.0)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to create budget",
            ))));
        }
    };

    Ok(HttpResponse::Created().json(new_budget))
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_access_token: BudgetAccessToken,
    budget_data: web::Json<InputEditBudget>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let budget_id = budget_access_token.claims.budget_id;
    let key_id = budget_access_token.claims.key_id;
    let public_key = obtain_public_key(key_id, budget_id, &db_thread_pool).await?;

    if !budget_access_token
        .0
        .verify_for_user(user_access_token.claims.user_id, &public_key.public_key)
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No budget with provided ID",
        ))));
    }

    if public_key.read_only == true {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "User has read-only access to budget",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_budget(
            budget_id,
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
                    "No budget with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
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
    budget_access_token: BudgetAccessToken,
    invitation_info: web::Json<UserInvitationToBudget>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let budget_id = budget_access_token.claims.budget_id;
    let key_id = budget_access_token.claims.key_id;
    let public_key = obtain_public_key(key_id, budget_id, &db_thread_pool).await?;

    if !budget_access_token
        .0
        .verify_for_user(user_access_token.claims.user_id, &public_key.public_key)
    {
        return Err(ServerError::NotFound(Some(String::from(
            "No budget with provided ID",
        ))));
    }

    if public_key.read_only == true {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "User has read-only access to budget",
        ))));
    }

    let inviting_user_id = user_access_token.claims.user_id;
    let inviting_user_email = user_access_token.claims.eml;

    if invitation_info.recipient_user_email == inviting_user_email {
        return Err(ServerError::InputRejected(Some(String::from(
            "Inviter and recipient are the same",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.invite_user(
            &invitation_info.recipient_user_email,
            &invitation_info.sender_public_key,
            &invitation_info.encryption_key_encrypted,
            &invitation_info.budget_share_private_key_encrypted,
            &invitation_info.budget_info_encrypted,
            &invitation_info.sender_info_encrypted,
            &invitation_info.budget_share_private_key_info_encrypted,
            &invitation_info.share_info_symmetric_key_encrypted,
            budget_id,
            &invitation_info.public_key,
            invitation_info.expiration,
            invitation_info.read_only,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            diesel::result::Error::NotFound => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget or invite with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to share budget",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Token proving ability to edit invitations
pub async fn retract_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invitation_id.share_invite_id, &user_access_token.claims.eml)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete invitation",
                ))));
            }
        },
    }

    Ok(HttpResponse::Ok().finish())
}

// TODO: Special new token -- budget acceptance token
pub async fn accept_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.claims.0?;

    let db_thread_pool_ref = db_thread_pool.clone();
    let share_invite_id = invitation_id.share_invite_id;

    let budget_key = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_ref);
        budget_dao.accept_invitation(
            share_invite_id,
            user_access_token.claims.user_id,
            &user_access_token.claims.eml,
        )
    })
    .await?
    {
        Ok(key) => key,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to accept invitation",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(budget_key))
}

pub async fn decline_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invitation_id.share_invite_id, &user_access_token.claims.eml)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share invite with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
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
    let user_access_token = user_access_token.0?;

    let invites = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_pending_invitations_for_user(&user_access_token.claims.eml)
    })
    .await?
    {
        Ok(invites) => invites,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputBudgetShareInviteWithoutKey>::new()));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find invitations",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invites))
}

// TODO: Figure this out
pub async fn get_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let invite = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_invitation(invitation_id.share_invite_id, &user_access_token.claims.eml)
    })
    .await?
    {
        Ok(invite) => invite,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "Share invite not found",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to find invitations",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().json(invite))
}

// TODO: Budget Access Token
pub async fn leave_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    budget_id: web::Query<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.leave_budget(budget_id.budget_id, user_access_token.claims.user_id)
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
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to remove association with budget",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn create_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    entry_data: web::Json<InputEncryptedBlob>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let entry_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry(entry_data.0, user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(OutputEntryId { entry_id }))
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn create_entry_and_category(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    entry_and_category_data: web::Json<InputEntryAndCategory>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let entry_and_category_ids = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao
            .create_entry_and_category(entry_and_category_data.0, user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(ids) => ids,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(entry_and_category_ids))
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn edit_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    entry_data: web::Query<InputEditEntry>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_entry(
            entry_data.entry_id,
            &entry_data.encrypted_blob,
            &entry_data.expected_previous_data_hash,
            user_access_token.claims.user_id,
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
                    "No entry with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn delete_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    entry_id: web::Query<InputEntryId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_entry(entry_id.0.entry_id, user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No entry with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to delete entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn create_category(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    category_data: web::Json<InputEncryptedBlob>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    let category_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_category(category_data.0, user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(OutputCategoryId { category_id }))
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn edit_category(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    category_data: web::Query<InputEditCategory>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_category(
            category_data.category_id,
            &category_data.encrypted_blob,
            &category_data.expected_previous_data_hash,
            user_access_token.claims.user_id,
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
                    "No category with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to update category",
                ))));
            }
        },
    };

    Ok(HttpResponse::Ok().finish())
}

// TODO: Budget Access Token
// TODO: Check user has write access
pub async fn delete_category(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<Access, FromHeader>,
    category_id: web::Query<InputCategoryId>,
) -> Result<HttpResponse, ServerError> {
    let user_access_token = user_access_token.0?;

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_category(category_id.0.category_id, user_access_token.claims.user_id)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No category with provided ID or user does not have edit privileges",
                ))));
            }
            _ => {
                log::error!("{}", e);
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
    let key = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_public_budget_key(key_id, budget_id)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID",
                ))));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get public budget access key",
                ))));
            }
        },
    };

    Ok(key)
}
