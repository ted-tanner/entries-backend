use budgetapp_utils::request_io::{
    InputBudget, InputBudgetId, InputBudgetIdList, InputCategory, InputCategoryId, InputEditBudget,
    InputEditCategory, InputEditEntry, InputEncryptedBudgetKey, InputEntry, InputEntryAndCategory,
    InputEntryId, InputShareInviteId, OutputBudget, OutputBudgetShareInviteWithoutKey,
    OutputCategoryId, OutputEntryId, UserInvitationToBudget,
};
use budgetapp_utils::{db, db::DaoError, db::DbThreadPool};

use crate::handlers::error::ServerError;
use crate::middleware::auth::AuthorizedUserClaims;
use actix_web::{web, HttpResponse};

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    budget_id: web::Query<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_budget_by_id(budget_id.budget_id, auth_user_claims.0.uid)
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
    auth_user_claims: AuthorizedUserClaims,
    budget_ids: web::Json<InputBudgetIdList>,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_multiple_budgets_by_id(budget_ids.0.budget_ids, auth_user_claims.0.uid)
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

pub async fn get_all(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_budgets_for_user(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Ok(HttpResponse::Ok().json(Vec::<OutputBudget>::new()));
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
    auth_user_claims: AuthorizedUserClaims,
    budget_data: web::Json<InputBudget>,
) -> Result<HttpResponse, ServerError> {
    let new_budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_budget(budget_data.0, auth_user_claims.0.uid)
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
    auth_user_claims: AuthorizedUserClaims,
    budget_data: web::Json<InputEditBudget>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_budget(
            budget_data.budget_id,
            &budget_data.encrypted_blob_b64,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to edit budget",
            ))));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn replace_key(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    key: web::Json<InputEncryptedBudgetKey>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_budget_key(
            key.budget_id,
            &key.encrypted_key,
            key.is_encrypted_with_aes,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to update key",
            ))));
        }
    };

    Ok(HttpResponse::Ok().finish())
}

pub async fn invite_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    invitation_info: web::Json<UserInvitationToBudget>,
) -> Result<HttpResponse, ServerError> {
    let inviting_user_id = auth_user_claims.0.uid;

    if invitation_info.invitee_user_id == inviting_user_id {
        return Err(ServerError::InputRejected(Some(String::from(
            "Inviter and invitee have the same ID",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.invite_user(
            invitation_info.budget_id,
            &invitation_info.budget_name_encrypted_b64,
            invitation_info.invitee_user_id,
            inviting_user_id,
            invitation_info.sender_name_encrypted_b64.as_deref(),
            &invitation_info.budget_encryption_key_encrypted_b64,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "Sending user has no budget with provided ID",
                ))));
            }
            DaoError::QueryFailure(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Invitatino was already sent",
                ))));
            }
            DaoError::WontRunQuery => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "This budget is already shared with this user",
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

pub async fn retract_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invitation_id.share_invite_id, auth_user_claims.0.uid)
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

pub async fn accept_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_ref = db_thread_pool.clone();
    let share_invite_id = invitation_id.share_invite_id;

    let budget_key = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_ref);
        budget_dao.accept_invitation(share_invite_id, auth_user_claims.0.uid)
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
    auth_user_claims: AuthorizedUserClaims,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invitation_id.share_invite_id, auth_user_claims.0.uid)
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
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let invites = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_pending_invitations_for_user(auth_user_claims.0.uid)
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

pub async fn get_all_pending_invitations_made_by_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let invites = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_pending_invitations_made_by_user(auth_user_claims.0.uid)
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

pub async fn get_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    invitation_id: web::Query<InputShareInviteId>,
) -> Result<HttpResponse, ServerError> {
    let invite = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_invitation(invitation_id.share_invite_id, auth_user_claims.0.uid)
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

pub async fn leave_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    budget_id: web::Query<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.leave_budget(budget_id.budget_id, auth_user_claims.0.uid)
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

pub async fn create_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    entry_data: web::Query<InputEntry>,
) -> Result<HttpResponse, ServerError> {
    let entry_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry(entry_data.0, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID",
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

pub async fn create_entry_and_category(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    entry_and_category_data: web::Query<InputEntryAndCategory>,
) -> Result<HttpResponse, ServerError> {
    let entry_and_category_ids = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry_and_category(entry_and_category_data.0, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(ids) => ids,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID",
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

pub async fn edit_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    entry_data: web::Query<InputEditEntry>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_entry(
            entry_data.entry_id,
            &entry_data.encrypted_blob_b64,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No entry with provided ID",
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

pub async fn delete_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    entry_id: web::Query<InputEntryId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_entry(entry_id.0.entry_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No entry with provided ID",
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

pub async fn create_category(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    category_data: web::Query<InputCategory>,
) -> Result<HttpResponse, ServerError> {
    let category_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_category(category_data.0, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No budget with provided ID",
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

pub async fn edit_category(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    category_data: web::Query<InputEditCategory>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.update_category(
            category_data.category_id,
            &category_data.encrypted_blob_b64,
            auth_user_claims.0.uid,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No category with provided ID",
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

pub async fn delete_category(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    category_id: web::Query<InputCategoryId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_category(category_id.0.category_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(id) => id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No category with provided ID",
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
