use budgetapp_utils::request_io::{
    InputBudget, InputBudgetId, InputDateRange, InputEditBudget, InputEntry, InputShareEventId,
    OutputBudget, UserInvitationToBudget,
};
use budgetapp_utils::{db, db::DaoError, db::DbThreadPool};

use actix_web::{web, HttpResponse};
use futures::try_join;
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

use crate::handlers::error::ServerError;
use crate::middleware;

pub async fn get(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
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

pub async fn get_all(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_budgets_for_user(auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
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

pub async fn get_all_between_dates(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    date_range: web::Query<InputDateRange>,
) -> Result<HttpResponse, ServerError> {
    let budgets = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_all_budgets_for_user_between_dates(
            auth_user_claims.0.uid,
            UNIX_EPOCH + Duration::from_secs(date_range.start_date),
            UNIX_EPOCH + Duration::from_secs(date_range.end_date),
        )
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None))
            }
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_data: web::Json<InputBudget>,
) -> Result<HttpResponse, ServerError> {
    let new_budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_budget(&budget_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create budget",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(new_budget))
}

pub async fn edit(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_data: web::Json<InputEditBudget>,
) -> Result<HttpResponse, ServerError> {
    if budget_data.start_date > budget_data.end_date {
        return Err(ServerError::InputRejected(Some(String::from(
            "End date cannot come before start date",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.edit_budget(&budget_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                Err(ServerError::NotFound(Some(String::from(
                    "Budget not found or no changes were made",
                ))))
            } else {
                Ok(HttpResponse::Ok().finish())
            }
        }
        Err(e) => {
            log::error!("{}", e);
            Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to edit budget",
            ))))
        }
    }
}

pub async fn add_entry(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    entry_data: web::Json<InputEntry>,
) -> Result<HttpResponse, ServerError> {
    let budget_id = entry_data.budget_id;

    let is_user_in_budget =
        check_user_in_budget(&db_thread_pool, auth_user_claims.0.uid, budget_id).await?;

    if !is_user_in_budget {
        return Err(ServerError::NotFound(Some(String::from(
            "User has no budget with provided ID",
        ))));
    }

    let new_entry = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.create_entry(&entry_data, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(b) => b,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
            }
            _ => {
                log::error!("{}", e);
                return Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to create entry",
                ))));
            }
        },
    };

    Ok(HttpResponse::Created().json(new_entry))
}

pub async fn invite_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_info: web::Json<UserInvitationToBudget>,
) -> Result<HttpResponse, ServerError> {
    let inviting_user_id = auth_user_claims.0.uid;

    if invitation_info.invitee_user_id == inviting_user_id {
        return Err(ServerError::InputRejected(Some(String::from(
            "Inviter and invitee have the same ID",
        ))));
    }

    let is_sender_in_budget_future =
        check_user_in_budget(&db_thread_pool, inviting_user_id, invitation_info.budget_id);

    let is_receiver_in_budget_future = check_user_in_budget(
        &db_thread_pool,
        invitation_info.invitee_user_id,
        invitation_info.budget_id,
    );

    let (is_sender_in_budget, is_receiver_in_budget) =
        try_join!(is_sender_in_budget_future, is_receiver_in_budget_future)?;

    if !is_sender_in_budget {
        return Err(ServerError::NotFound(Some(String::from(
            "User has no budget with provided ID",
        ))));
    };

    if is_receiver_in_budget {
        return Err(ServerError::InputRejected(Some(String::from(
            "User already has access to budget",
        ))));
    }

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.invite_user(
            invitation_info.budget_id,
            invitation_info.invitee_user_id,
            inviting_user_id,
        )
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                return Err(ServerError::InvalidFormat(None));
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Query<InputShareEventId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.delete_invitation(invitation_id.share_event_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share event belonging to user with provided ID",
                ))));
            }
        }
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share event with provided ID",
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Query<InputShareEventId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_ref = db_thread_pool.clone();
    let share_event_id = invitation_id.share_event_id;

    let budget_id = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_ref);
        budget_dao.mark_invitation_accepted(share_event_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(share_event) => share_event.budget_id,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share event with provided ID",
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

    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.add_user(budget_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to accept invitation",
            ))));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn decline_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Query<InputShareEventId>,
) -> Result<HttpResponse, ServerError> {
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.mark_invitation_declined(invitation_id.share_event_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => {
            if count == 0 {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share event with provided ID",
                ))));
            }
        }
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "No share event with provided ID",
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
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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
                return Err(ServerError::NotFound(Some(String::from(
                    "No share events for user",
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

    Ok(HttpResponse::Ok().json(invites))
}

pub async fn get_all_pending_invitations_made_by_user(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
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
                return Err(ServerError::NotFound(Some(String::from(
                    "No share events made by user",
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

    Ok(HttpResponse::Ok().json(invites))
}

pub async fn get_invitation(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    invitation_id: web::Query<InputShareEventId>,
) -> Result<HttpResponse, ServerError> {
    let invite = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.get_invitation(invitation_id.share_event_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(invite) => invite,
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::NotFound) => {
                return Err(ServerError::NotFound(Some(String::from(
                    "Share event not found",
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

pub async fn remove_budget(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: middleware::auth::AuthorizedUserClaims,
    budget_id: web::Query<InputBudgetId>,
) -> Result<HttpResponse, ServerError> {
    let db_thread_pool_clone = db_thread_pool.clone();
    let db_thread_pool_second_clone = db_thread_pool.clone();

    let budget_id_clone = budget_id.0.clone();
    let budget_id_second_clone = budget_id.0.clone();

    let rows_affected_count = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool);
        budget_dao.remove_user(budget_id.budget_id, auth_user_claims.0.uid)
    })
    .await?
    {
        Ok(count) => count,
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

    if rows_affected_count == 0 {
        return Err(ServerError::NotFound(Some(String::from(
            "User budget association not found",
        ))));
    }

    // TODO: Perhaps user shouldn't have to wait for this (make it non-blocking). Users have
    //       already been removed from the budget, so the handler can return without finishing
    //       deleting the budget.
    //
    //       Perhaps create a thread or threadpool (in another module) with a queue. The thread
    //       just polls the queue and executes closures from the queue. This delete operation
    //       could be added to that queue.
    let remaining_users_in_budget = match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_clone);
        budget_dao.count_users_remaining_in_budget(budget_id_clone.budget_id)
    })
    .await?
    {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "Failed to get count of how many users are left in budget with ID '{}': {}",
                budget_id_clone.budget_id,
                e
            );
            10
        }
    };

    if remaining_users_in_budget == 0 {
        match web::block(move || {
            let mut budget_dao = db::budget::Dao::new(&db_thread_pool_second_clone);
            budget_dao.delete_budget(budget_id_second_clone.budget_id)
        })
        .await?
        {
            Ok(_) => (),
            Err(e) => {
                log::error!(
                    "Failed to delete budget with ID '{}': {}",
                    budget_id_second_clone.budget_id,
                    e
                );
            }
        };
    }

    Ok(HttpResponse::Ok().finish())
}

async fn check_user_in_budget(
    db_thread_pool: &DbThreadPool,
    user_id: Uuid,
    budget_id: Uuid,
) -> Result<bool, ServerError> {
    let db_thread_pool_clone = db_thread_pool.clone();
    match web::block(move || {
        let mut budget_dao = db::budget::Dao::new(&db_thread_pool_clone);
        budget_dao.check_user_in_budget(user_id, budget_id)
    })
    .await?
    {
        Ok(b) => Ok(b),
        Err(e) => match e {
            DaoError::QueryFailure(diesel::result::Error::InvalidCString(_))
            | DaoError::QueryFailure(diesel::result::Error::DeserializationError(_)) => {
                Err(ServerError::InvalidFormat(None))
            }
            _ => {
                log::error!("{}", e);
                Err(ServerError::DatabaseTransactionError(Some(String::from(
                    "Failed to get budget data",
                ))))
            }
        },
    }
}

#[cfg(test)]
pub mod tests {
    use budgetapp_utils::auth_token::TokenClaims;
    use budgetapp_utils::models::budget::Budget;
    use budgetapp_utils::models::budget_share_event::BudgetShareEvent;
    use budgetapp_utils::models::category::Category;
    use budgetapp_utils::models::entry::Entry;
    use budgetapp_utils::models::user_budget::UserBudget;
    use budgetapp_utils::request_io::{
        InputBudget, InputBudgetId, InputCategory, InputDateRange, InputEditBudget, InputEntry,
        InputShareEventId, InputUser, OutputBudget, SigninToken, SigninTokenOtpPair, TokenPair,
        UserInvitationToBudget,
    };
    use budgetapp_utils::schema::budget_share_events as budget_share_event_fields;
    use budgetapp_utils::schema::budget_share_events::dsl::budget_share_events;
    use budgetapp_utils::schema::budgets as budget_fields;
    use budgetapp_utils::schema::budgets::dsl::budgets;
    use budgetapp_utils::schema::categories as category_fields;
    use budgetapp_utils::schema::entries as entry_fields;
    use budgetapp_utils::schema::user_budgets as user_budget_fields;
    use budgetapp_utils::schema::user_budgets::dsl::user_budgets;
    use budgetapp_utils::{db, otp};

    use actix_web::web::Data;
    use actix_web::{http, test, App};
    use diesel::prelude::*;
    use rand::prelude::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use crate::env;
    use crate::handlers::user::tests::create_user_and_sign_in;
    use crate::services;

    #[derive(Clone)]
    pub struct UserAndBudgetWithAuthTokens {
        pub budget: OutputBudget,
        pub user_id: Uuid,
        pub token_pair: TokenPair,
    }

    pub async fn create_user_and_budget_and_sign_in() -> UserAndBudgetWithAuthTokens {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_and_tokens = create_user_and_sign_in().await;
        let user_id = &user_and_tokens.user.id;
        let access_token = &user_and_tokens.token_pair.access_token;

        let rand_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {rand_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {rand_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {rand_number}"),
            description: Some(format!(
                "This is a description of Test Budget {rand_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(200_000_000..300_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_res = test::call_service(&app, create_budget_req).await;
        let create_budget_res_body =
            String::from_utf8(actix_web::test::read_body(create_budget_res).await.to_vec())
                .unwrap();

        let budget = serde_json::from_str::<OutputBudget>(create_budget_res_body.as_str()).unwrap();

        UserAndBudgetWithAuthTokens {
            budget,
            user_id: *user_id,
            token_pair: user_and_tokens.token_pair,
        }
    }

    #[actix_rt::test]
    async fn test_create_budget() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);
        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),
            password: String::from("tNmUV%9$khHK2TqOLw*%W"),
            first_name: format!("Test-{}", &user_number),
            last_name: format!("User-{}", &user_number),
            date_of_birth: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..1_000_000_000)),
            currency: String::from("USD"),
        };

        let create_user_res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/user/create")
                .insert_header(("content-type", "application/json"))
                .set_payload(serde_json::ser::to_vec(&new_user).unwrap())
                .to_request(),
        )
        .await;

        let signin_token = test::read_body_json::<SigninToken, _>(create_user_res).await;
        let user_id = TokenClaims::from_token_without_validation(&signin_token.signin_token)
            .unwrap()
            .uid;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = otp::generate_otp(
            user_id,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )
        .unwrap();

        let token_and_otp = SigninTokenOtpPair {
            signin_token: signin_token.signin_token,
            otp: otp.to_string(),
        };

        let otp_req = test::TestRequest::post()
            .uri("/api/auth/verify_otp_for_signin")
            .insert_header(("content-type", "application/json"))
            .set_payload(serde_json::ser::to_vec(&token_and_otp).unwrap())
            .to_request();

        let otp_res = test::call_service(&app, otp_req).await;
        let token_pair = actix_web::test::read_body_json::<TokenPair, _>(otp_res).await;
        let access_token = token_pair.access_token.to_string();

        let category0 = InputCategory {
            id: 0,
            name: format!("First Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: format!("Second Random Category {user_number}"),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: format!("Test Budget {user_number}"),
            description: Some(format!(
                "This is a description of Test Budget {user_number}.",
            )),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let created_budget = budgets
            .filter(budget_fields::name.eq(&new_budget.name))
            .filter(budget_fields::start_date.eq(&new_budget.start_date))
            .first::<Budget>(&mut db_connection)
            .unwrap();

        let created_categories = Category::belonging_to(&created_budget)
            .order(category_fields::id.asc())
            .load::<Category>(&mut db_connection)
            .unwrap();

        let created_entries = Entry::belonging_to(&created_budget)
            .order(entry_fields::created_timestamp.asc())
            .load::<Entry>(&mut db_connection)
            .unwrap();

        assert_eq!(&new_budget.name, &created_budget.name);
        assert_eq!(&new_budget.description, &created_budget.description);
        assert_eq!(&new_budget.start_date, &created_budget.start_date);
        assert_eq!(&new_budget.end_date, &created_budget.end_date);

        assert!(created_entries.is_empty());

        for (i, created_cat) in created_categories.iter().enumerate() {
            let new_cat = &new_budget.categories[i];

            assert_eq!(created_cat.budget_id, created_budget.id);
            assert_eq!(created_cat.id, new_cat.id);
            assert_eq!(created_cat.name, new_cat.name);
            assert_eq!(created_cat.limit_cents, new_cat.limit_cents);
            assert_eq!(created_cat.color, new_cat.color);
        }
    }

    #[actix_rt::test]
    async fn test_edit_budget() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user_id = created_user_and_budget.user_id;
        let budget_before_edit = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id,
            name: "Test Budget user after edit".to_string(),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date,
            end_date: SystemTime::now(),
        };

        let req = test::TestRequest::put()
            .uri("/api/budget/edit")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&edit_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let mut budget_dao = db::budget::Dao::new(&env::testing::DB_THREAD_POOL);

        let budget_after_edit = budget_dao
            .get_budget_by_id(budget_before_edit.id, created_user_id)
            .unwrap();

        assert_eq!(&budget_after_edit.name, &edit_budget.name);
        assert_eq!(&budget_after_edit.description, &edit_budget.description);
        assert_eq!(&budget_after_edit.start_date, &edit_budget.start_date);
        assert_eq!(&budget_after_edit.end_date, &edit_budget.end_date);
    }

    #[actix_rt::test]
    async fn test_cannot_edit_budget_of_another_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget1 = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user_and_budget1.user_id;

        let created_user_and_budget2 = create_user_and_budget_and_sign_in().await;

        let budget_before_edit = created_user_and_budget1.budget.clone();
        let access_token = created_user_and_budget2.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id,
            name: "Test Budget user after edit".to_string(),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date,
            end_date: SystemTime::now(),
        };

        let req = test::TestRequest::put()
            .uri("/api/budget/edit")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&edit_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let mut budget_dao = db::budget::Dao::new(&env::testing::DB_THREAD_POOL);

        let budget_after_edit = budget_dao
            .get_budget_by_id(budget_before_edit.id, created_user1_id)
            .unwrap();

        assert_eq!(&budget_after_edit.name, &budget_before_edit.name);
        assert_eq!(
            &budget_after_edit.description,
            &budget_before_edit.description
        );
        assert_eq!(
            &budget_after_edit.start_date,
            &budget_before_edit.start_date
        );
        assert_eq!(&budget_after_edit.end_date, &budget_before_edit.end_date);
    }

    #[actix_rt::test]
    async fn test_edit_budget_start_cannot_be_after_end() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user_id = created_user_and_budget.user_id;
        let budget_before_edit = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let edit_budget = InputEditBudget {
            id: budget_before_edit.id,
            name: "Test Budget user after edit".to_string(),
            description: budget_before_edit.description.clone(),
            start_date: budget_before_edit.start_date,
            end_date: UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(50_000_000..100_000_000)),
        };

        let req = test::TestRequest::put()
            .uri("/api/budget/edit")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&edit_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let mut budget_dao = db::budget::Dao::new(&env::testing::DB_THREAD_POOL);

        let budget_after_edit = budget_dao
            .get_budget_by_id(budget_before_edit.id, created_user_id)
            .unwrap();

        assert_eq!(&budget_after_edit.name, &budget_before_edit.name);
        assert_eq!(
            &budget_after_edit.description,
            &budget_before_edit.description
        );
        assert_eq!(
            &budget_after_edit.start_date,
            &budget_before_edit.start_date
        );
        assert_eq!(&budget_after_edit.end_date, &budget_before_edit.end_date);
    }

    #[actix_rt::test]
    async fn test_add_entry() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let user_id = created_user_and_budget.user_id;
        let budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let entry0 = InputEntry {
            budget_id: budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let new_entries = vec![entry0.clone(), entry1.clone()];

        let req0 = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_entries[0])
            .to_request();

        let resp0 = test::call_service(&app, req0).await;
        assert_eq!(resp0.status(), http::StatusCode::CREATED);

        let req1 = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_entries[1])
            .to_request();

        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), http::StatusCode::CREATED);

        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let budget_id = InputBudgetId {
            budget_id: budget.id,
        };

        let fetched_budget_req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let fetched_budget_resp = test::call_service(&app, fetched_budget_req).await;
        let fetched_budget_res_body = String::from_utf8(
            actix_web::test::read_body(fetched_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let budget =
            serde_json::from_str::<OutputBudget>(fetched_budget_res_body.as_str()).unwrap();

        let created_budget = budgets
            .find(budget.id)
            .first::<Budget>(&mut db_connection)
            .unwrap();

        let created_entries = Entry::belonging_to(&created_budget)
            .order(entry_fields::date.asc())
            .load::<Entry>(&mut db_connection)
            .unwrap();

        for i in 0..created_entries.len() {
            assert_eq!(created_entries[i].budget_id, new_entries[i].budget_id);
            assert_eq!(created_entries[i].user_id, Some(user_id));
            assert_eq!(created_entries[i].amount_cents, new_entries[i].amount_cents);
            assert_eq!(created_entries[i].date, new_entries[i].date);
            assert_eq!(created_entries[i].name, new_entries[i].name);
            assert_eq!(created_entries[i].category, new_entries[i].category);
            assert_eq!(created_entries[i].note, new_entries[i].note);
        }
    }

    #[actix_rt::test]
    async fn test_invite_user_and_accept() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_share = SystemTime::now();

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);
        assert!(share_events[0].accepted_declined_timestamp.is_none());

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);
        assert!(share_events[0].accepted_declined_timestamp.is_some());

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(budget_association.user_id, created_user2_id);
        assert_eq!(budget_association.budget_id, created_user1_budget.id);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_cannot_accept_invites_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget = create_user_and_budget_and_sign_in().await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        let instant_after_share = SystemTime::now();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert!(!share_events[0].accepted);
        assert!(share_events[0].accepted_declined_timestamp.is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert!(!share_events[0].accepted);
        assert!(share_events[0].accepted_declined_timestamp.is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_invite_user_and_decline() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        let instant_after_share = SystemTime::now();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/decline_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_err());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_cannot_decline_invites_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget = create_user_and_budget_and_sign_in().await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        let instant_after_share = SystemTime::now();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_none());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let input_budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/decline_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert!(!share_events[0].accepted);
        assert!(share_events[0].accepted_declined_timestamp.is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/decline_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert!(!share_events[0].accepted);
        assert!(share_events[0].accepted_declined_timestamp.is_none());

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/decline_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);
        assert_eq!(share_events[0].recipient_user_id, created_user2_id);
        assert_eq!(share_events[0].sender_user_id, created_user1_id);
        assert!(!share_events[0].accepted);

        assert!(share_events[0].accepted_declined_timestamp.is_some());
        assert!(share_events[0].created_timestamp > instant_before_share);
        assert!(share_events[0].created_timestamp < instant_after_share);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_retract_invitation() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/retract_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);
    }

    #[actix_rt::test]
    async fn test_cannot_retract_invites_made_by_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget = create_user_and_budget_and_sign_in().await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/retract_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/retract_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/retract_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);
    }

    #[actix_rt::test]
    async fn test_get_all_invitations_for_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget1 = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let category0 = InputCategory {
            id: 0,
            name: "First Random Category for user1_budget2".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: "Second Random Category user1_budget2".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: "Test Budget #2".to_string(),
            description: Some("This is a description of Test Budget #2.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_resp_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_user1_budget2 =
            serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

        let invitation_info_budget1 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget1.id,
        };

        let invitation_info_budget2 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget2.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget1)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget2)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/budget/get_all_pending_invitations_for_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let invitations =
            serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();

        assert_eq!(invitations.len(), 2);

        let budget1_invitation = &invitations[0];
        let budget2_invitation = &invitations[1];

        assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget1_invitation.sender_user_id, created_user1_id);
        assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
        assert!(!budget1_invitation.accepted);
        assert!(budget1_invitation.accepted_declined_timestamp.is_none());

        assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget2_invitation.sender_user_id, created_user1_id);
        assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
        assert!(!budget2_invitation.accepted);
        assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    }

    #[actix_rt::test]
    async fn test_get_all_invitations_made_by_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget1 = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();

        let category0 = InputCategory {
            id: 0,
            name: "First Random Category for user1_budget2".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: "Second Random Category user1_budget2".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0, category1];

        let new_budget = InputBudget {
            name: "Test Budget #2".to_string(),
            description: Some("This is a description of Test Budget #2.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let create_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&new_budget)
            .to_request();

        let create_budget_resp = test::call_service(&app, create_budget_req).await;
        let create_budget_resp_body = String::from_utf8(
            actix_web::test::read_body(create_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_user1_budget2 =
            serde_json::from_str::<OutputBudget>(create_budget_resp_body.as_str()).unwrap();

        let invitation_info_budget1 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget1.id,
        };

        let invitation_info_budget2 = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget2.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget1)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget2)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri("/api/budget/get_all_pending_invitations_made_by_user")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let invitations =
            serde_json::from_str::<Vec<BudgetShareEvent>>(resp_body.as_str()).unwrap();

        assert_eq!(invitations.len(), 2);

        let budget1_invitation = &invitations[0];
        let budget2_invitation = &invitations[1];

        assert_eq!(budget1_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget1_invitation.sender_user_id, created_user1_id);
        assert_eq!(budget1_invitation.budget_id, created_user1_budget1.id);
        assert!(!budget1_invitation.accepted);
        assert!(budget1_invitation.accepted_declined_timestamp.is_none());

        assert_eq!(budget2_invitation.recipient_user_id, created_user2_id);
        assert_eq!(budget2_invitation.sender_user_id, created_user1_id);
        assert_eq!(budget2_invitation.budget_id, created_user1_budget2.id);
        assert!(!budget2_invitation.accepted);
        assert!(budget2_invitation.accepted_declined_timestamp.is_none());
    }

    #[actix_rt::test]
    async fn test_get_invitation() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget = create_user_and_budget_and_sign_in().await;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info_budget = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let instant_before_share = SystemTime::now();

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let instant_after_share = SystemTime::now();

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let invitation = serde_json::from_str::<BudgetShareEvent>(resp_body.as_str()).unwrap();

        assert_eq!(invitation.recipient_user_id, created_user2_id);
        assert_eq!(invitation.sender_user_id, created_user1_id);
        assert!(!invitation.accepted);

        assert!(invitation.accepted_declined_timestamp.is_none());
        assert!(invitation.created_timestamp > instant_before_share);
        assert!(invitation.created_timestamp < instant_after_share);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let resp_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let invitation = serde_json::from_str::<BudgetShareEvent>(resp_body.as_str()).unwrap();

        assert_eq!(invitation.recipient_user_id, created_user2_id);
        assert_eq!(invitation.sender_user_id, created_user1_id);
        assert!(!invitation.accepted);

        assert!(invitation.accepted_declined_timestamp.is_none());
        assert!(invitation.created_timestamp > instant_before_share);
        assert!(invitation.created_timestamp < instant_after_share);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_remove_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget = created_user1_and_budget.budget;
        let created_user1_id = created_user1_and_budget.user_id;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info_budget = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(budget_association.user_id, created_user2_id);
        assert_eq!(budget_association.budget_id, created_user1_budget.id);

        let budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1); // Share event still exists

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_err());

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user1_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_ok());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        // Make sure a new invitation can be sent again
        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(budget_association.user_id, created_user2_id);
        assert_eq!(budget_association.budget_id, created_user1_budget.id);
    }

    #[actix_rt::test]
    async fn test_remove_last_user_deletes_budget() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_id = created_user1_and_budget.user_id;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;
        let created_user2_budget = created_user2_and_budget.budget;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();

        let invitation_info_budget = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection)
            .unwrap();

        assert_eq!(budget_association.user_id, created_user2_id);
        assert_eq!(budget_association.budget_id, created_user1_budget.id);

        let budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget = budgets
            .find(created_user1_budget.id)
            .load::<Budget>(&mut db_connection);

        assert!(budget.is_ok());

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user2_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 0);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user1_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_err());

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user1_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_err());

        let budget = budgets
            .find(created_user1_budget.id)
            .get_result::<Budget>(&mut db_connection);

        assert!(budget.is_err());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let budget_user2_id = InputBudgetId {
            budget_id: created_user2_budget.id,
        };

        let req = test::TestRequest::delete()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                budget_user2_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_association = user_budgets
            .filter(user_budget_fields::user_id.eq(created_user2_id))
            .filter(user_budget_fields::budget_id.eq(created_user2_budget.id))
            .first::<UserBudget>(&mut db_connection);

        assert!(budget_association.is_err());

        let budget = budgets
            .find(created_user2_budget.id)
            .get_result::<Budget>(&mut db_connection);

        assert!(budget.is_err());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_user2_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_cannot_delete_budget_for_another_user() {
        let mut db_connection = env::testing::DB_THREAD_POOL.get().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user1_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user1_budget = created_user1_and_budget.budget;

        let created_user2_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user2_id = created_user2_and_budget.user_id;

        let created_user3_and_budget = create_user_and_budget_and_sign_in().await;
        let created_user3_budget = created_user3_and_budget.budget;

        let user1_access_token = created_user1_and_budget.token_pair.access_token.clone();
        let user2_access_token = created_user2_and_budget.token_pair.access_token.clone();
        let user3_access_token = created_user3_and_budget.token_pair.access_token.clone();

        let invitation_info_budget = UserInvitationToBudget {
            invitee_user_id: created_user2_id,
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri("/api/budget/invite")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .set_json(&invitation_info_budget)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let share_events = budget_share_events
            .filter(budget_share_event_fields::budget_id.eq(created_user1_budget.id))
            .load::<BudgetShareEvent>(&mut db_connection)
            .unwrap();

        assert_eq!(share_events.len(), 1);

        let invite_id = InputShareEventId {
            share_event_id: share_events[0].id,
        };

        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/budget/accept_invitation?share_event_id={}",
                invite_id.share_event_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let budget_id = InputBudgetId {
            budget_id: created_user1_budget.id,
        };

        let req = test::TestRequest::post()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let budget = budgets
            .find(created_user1_budget.id)
            .load::<Budget>(&mut db_connection);

        assert!(budget.is_ok());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user2_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let user3_budget_id = InputBudgetId {
            budget_id: created_user3_budget.id,
        };

        let req = test::TestRequest::post()
            .uri(&format!(
                "/api/budget/remove_budget?budget_id={}",
                user3_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user1_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let budget = budgets
            .find(created_user3_budget.id)
            .load::<Budget>(&mut db_connection);

        assert!(budget.is_ok());

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                user3_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {user3_access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_get_budget() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();
        let budget_categories = created_budget.categories.clone();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..600_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[0])
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[1])
            .to_request();

        test::call_service(&app, entry1_req).await;

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let budget = serde_json::from_str::<OutputBudget>(res_body.as_str()).unwrap();

        assert_eq!(budget.id, created_budget.id);
        assert_eq!(budget.is_private, created_budget.is_private);
        assert_eq!(budget.is_deleted, created_budget.is_deleted);
        assert_eq!(budget.name, created_budget.name);
        assert_eq!(budget.description, created_budget.description);
        assert_eq!(budget.start_date, created_budget.start_date);
        assert_eq!(budget.end_date, created_budget.end_date);

        assert!(budget.latest_entry_time > created_budget.latest_entry_time);

        assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
        assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

        assert!(!budget.categories.is_empty());
        assert_eq!(budget.categories.len(), created_budget.categories.len());

        for (i, fetched_cat) in budget_categories.iter().enumerate() {
            let created_cat = &created_budget.categories[i];

            assert_eq!(fetched_cat.pk, created_cat.pk);
            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }

        for (i, created_entry) in created_entries.iter().enumerate() {
            assert_eq!(budget.entries[i].amount_cents, created_entry.amount_cents);
            assert_eq!(budget.entries[i].date, created_entry.date);
            assert_eq!(budget.entries[i].name, created_entry.name);
            assert_eq!(budget.entries[i].category, created_entry.category);
            assert_eq!(budget.entries[i].note, created_entry.note);
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_budget0 = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let budget_categories = vec![
            InputCategory {
                id: created_budget0.categories[0].id,
                name: created_budget0.categories[0].name.clone(),
                limit_cents: created_budget0.categories[0].limit_cents,
                color: created_budget0.categories[0].color.clone(),
            },
            InputCategory {
                id: created_budget0.categories[1].id,
                name: created_budget0.categories[1].name.clone(),
                limit_cents: created_budget0.categories[1].limit_cents,
                color: created_budget0.categories[1].color.clone(),
            },
        ];

        let new_budget1 = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..700_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let create_budget1_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&new_budget1)
            .to_request();

        let create_budget1_resp = test::call_service(&app, create_budget1_req).await;
        let create_budget1_res_body = String::from_utf8(
            actix_web::test::read_body(create_budget1_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_budget1 =
            serde_json::from_str::<OutputBudget>(create_budget1_res_body.as_str()).unwrap();

        let created_budgets = vec![created_budget0.clone(), created_budget1.clone()];

        let entry0 = InputEntry {
            budget_id: created_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..600_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..600_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![
            vec![entry0.clone(), entry1.clone()],
            vec![entry2.clone(), entry3.clone()],
        ];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry0)
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry1)
            .to_request();

        test::call_service(&app, entry1_req).await;

        let entry2_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry2)
            .to_request();

        test::call_service(&app, entry2_req).await;

        let entry3_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry3)
            .to_request();

        test::call_service(&app, entry3_req).await;

        let req = test::TestRequest::get()
            .uri("/api/budget/get_all")
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let mut output_budgets =
            serde_json::from_str::<Vec<OutputBudget>>(res_body.as_str()).unwrap();
        assert_eq!(output_budgets.len(), 2);

        if output_budgets[0].id != created_budgets[0].id {
            output_budgets.reverse();
        }

        for i in 0..output_budgets.len() {
            let budget = &output_budgets[i];
            let created_budget = &created_budgets[i];

            assert_eq!(budget.id, created_budget.id);
            assert_eq!(budget.is_private, created_budget.is_private);
            assert_eq!(budget.is_deleted, created_budget.is_deleted);
            assert_eq!(budget.name, created_budget.name);
            assert_eq!(budget.description, created_budget.description);
            assert_eq!(budget.start_date, created_budget.start_date);
            assert_eq!(budget.end_date, created_budget.end_date);

            assert!(budget.latest_entry_time > created_budget.latest_entry_time);

            assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
            assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

            assert!(!budget.categories.is_empty());
            assert_eq!(budget.categories.len(), created_budget.categories.len());

            for j in 0..budget_categories.len() {
                let fetched_cat = &budget.categories[j];
                let created_cat = &created_budget.categories[j];

                assert_eq!(fetched_cat.pk, created_cat.pk);
                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }

            for j in 0..created_entries[i].len() {
                assert_eq!(
                    budget.entries[j].amount_cents,
                    created_entries[i][j].amount_cents
                );
                assert_eq!(budget.entries[j].date, created_entries[i][j].date);
                assert_eq!(budget.entries[j].name, created_entries[i][j].name);
                assert_eq!(budget.entries[j].category, created_entries[i][j].category);
                assert_eq!(budget.entries[j].note, created_entries[i][j].note);
            }
        }
    }

    #[actix_rt::test]
    async fn test_get_all_budgets_for_user_between_dates() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        diesel::delete(budgets.find(created_budget.id))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let category0 = InputCategory {
            id: 0,
            name: "First Random Category user".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#ff11ee"),
        };

        let category1 = InputCategory {
            id: 1,
            name: "Second Random Category user".to_string(),
            limit_cents: rand::thread_rng().gen_range(100..500),
            color: String::from("#112233"),
        };

        let budget_categories = vec![category0.clone(), category1.clone()];

        let too_early_budget = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(0..100_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(100_000_000..200_000_000)),
        };

        let create_too_early_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&too_early_budget)
            .to_request();

        let create_too_early_budget_resp =
            test::call_service(&app, create_too_early_budget_req).await;
        let create_too_early_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_too_early_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_too_early_budget =
            serde_json::from_str::<OutputBudget>(create_too_early_budget_res_body.as_str())
                .unwrap();

        let in_range_budget0 = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(300_000_000..400_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
        };

        let create_in_range_budget0_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget0)
            .to_request();

        let create_in_range_budget0_resp =
            test::call_service(&app, create_in_range_budget0_req).await;
        let create_in_range_budget0_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget0_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget0 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget0_res_body.as_str())
                .unwrap();

        let in_range_budget1 = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
        };

        let create_in_range_budget1_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget1)
            .to_request();

        let create_in_range_budget1_resp =
            test::call_service(&app, create_in_range_budget1_req).await;
        let create_in_range_budget1_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget1_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget1 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget1_res_body.as_str())
                .unwrap();

        let in_range_budget2 = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(600_000_000..700_000_000)),
        };

        let create_in_range_budget2_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&in_range_budget2)
            .to_request();

        let create_in_range_budget2_resp =
            test::call_service(&app, create_in_range_budget2_req).await;
        let create_in_range_budget2_res_body = String::from_utf8(
            actix_web::test::read_body(create_in_range_budget2_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_in_range_budget2 =
            serde_json::from_str::<OutputBudget>(create_in_range_budget2_res_body.as_str())
                .unwrap();

        let too_late_budget = InputBudget {
            name: "Test Budget user".to_string(),
            description: Some("This is a description of Test Budget user.".to_string()),
            categories: budget_categories.clone(),
            start_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(800_000_000..900_000_000)),
            end_date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
        };

        let create_too_late_budget_req = test::TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&too_late_budget)
            .to_request();

        let create_too_late_budget_resp =
            test::call_service(&app, create_too_late_budget_req).await;
        let create_too_late_budget_res_body = String::from_utf8(
            actix_web::test::read_body(create_too_late_budget_resp)
                .await
                .to_vec(),
        )
        .unwrap();

        let created_too_late_budget =
            serde_json::from_str::<OutputBudget>(create_too_late_budget_res_body.as_str()).unwrap();

        let in_range_budgets = vec![
            created_in_range_budget0.clone(),
            created_in_range_budget1.clone(),
            created_in_range_budget2.clone(),
        ];

        let entry0 = InputEntry {
            budget_id: created_too_early_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(100_000_000..200_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_too_early_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(200_000_000..300_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let entry2 = InputEntry {
            budget_id: created_in_range_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(300_000_000..400_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry3 = InputEntry {
            budget_id: created_in_range_budget0.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..500_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let entry4 = InputEntry {
            budget_id: created_in_range_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(500_000_000..600_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry5 = InputEntry {
            budget_id: created_in_range_budget1.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(600_000_000..700_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let entry6 = InputEntry {
            budget_id: created_in_range_budget2.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(700_000_000..800_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry7 = InputEntry {
            budget_id: created_in_range_budget2.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(800_000_000..900_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let entry8 = InputEntry {
            budget_id: created_too_late_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
            name: Some("Test Entry 2 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry9 = InputEntry {
            budget_id: created_too_late_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(1_000_000_000..1_100_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let in_range_budget_entries = vec![
            vec![entry2.clone(), entry3.clone()],
            vec![entry4.clone(), entry5.clone()],
            vec![entry6.clone(), entry7.clone()],
        ];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry0)
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry1)
            .to_request();

        test::call_service(&app, entry1_req).await;

        let entry2_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry2)
            .to_request();

        test::call_service(&app, entry2_req).await;

        let entry3_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry3)
            .to_request();

        test::call_service(&app, entry3_req).await;

        let entry4_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry4)
            .to_request();

        test::call_service(&app, entry4_req).await;

        let entry5_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry5)
            .to_request();

        test::call_service(&app, entry5_req).await;

        let entry6_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry6)
            .to_request();

        test::call_service(&app, entry6_req).await;

        let entry7_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry7)
            .to_request();

        test::call_service(&app, entry7_req).await;

        let entry8_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry8)
            .to_request();

        test::call_service(&app, entry8_req).await;

        let entry9_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&entry9)
            .to_request();

        test::call_service(&app, entry9_req).await;

        let date_range = InputDateRange {
            start_date: 300_000_000,
            end_date: 700_000_000,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get_all_between_dates?start_date={}&end_date={}",
                date_range.start_date, date_range.end_date,
            ))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(resp).await.to_vec()).unwrap();
        let output_budgets = serde_json::from_str::<Vec<OutputBudget>>(res_body.as_str()).unwrap();

        assert_eq!(output_budgets.len(), 3);

        for i in 0..output_budgets.len() {
            let budget = &output_budgets[i];
            let created_budget = &in_range_budgets[i];

            assert_eq!(budget.id, created_budget.id);
            assert_eq!(budget.is_private, created_budget.is_private);
            assert_eq!(budget.is_deleted, created_budget.is_deleted);
            assert_eq!(budget.name, created_budget.name);
            assert_eq!(budget.description, created_budget.description);
            assert_eq!(budget.start_date, created_budget.start_date);
            assert_eq!(budget.end_date, created_budget.end_date);

            assert!(budget.latest_entry_time > created_budget.latest_entry_time);

            assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
            assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

            assert!(!budget.categories.is_empty());
            assert_eq!(budget.categories.len(), created_budget.categories.len());

            for j in 0..budget_categories.len() {
                let fetched_cat = &budget.categories[j];
                let created_cat = &created_budget.categories[j];

                assert_eq!(fetched_cat.pk, created_cat.pk);
                assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
                assert_eq!(fetched_cat.id, created_cat.id);
                assert_eq!(fetched_cat.name, created_cat.name);
                assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
                assert_eq!(fetched_cat.color, created_cat.color);
            }

            for j in 0..in_range_budget_entries[i].len() {
                assert_eq!(
                    budget.entries[j].amount_cents,
                    in_range_budget_entries[i][j].amount_cents
                );
                assert_eq!(budget.entries[j].date, in_range_budget_entries[i][j].date);
                assert_eq!(budget.entries[j].name, in_range_budget_entries[i][j].name);
                assert_eq!(
                    budget.entries[j].category,
                    in_range_budget_entries[i][j].category
                );
                assert_eq!(budget.entries[j].note, in_range_budget_entries[i][j].note);
            }
        }
    }

    #[actix_rt::test]
    async fn test_cant_access_budget_for_another_user() {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .configure(services::api::configure),
        )
        .await;

        let created_user_and_budget = create_user_and_budget_and_sign_in().await;
        let created_budget = created_user_and_budget.budget.clone();
        let access_token = created_user_and_budget.token_pair.access_token.clone();

        let budget_categories = vec![
            InputCategory {
                id: created_budget.categories[0].id,
                name: created_budget.categories[0].name.clone(),
                limit_cents: created_budget.categories[0].limit_cents,
                color: created_budget.categories[0].color.clone(),
            },
            InputCategory {
                id: created_budget.categories[1].id,
                name: created_budget.categories[1].name.clone(),
                limit_cents: created_budget.categories[1].limit_cents,
                color: created_budget.categories[1].color.clone(),
            },
        ];

        let created_unauth_user_and_budget = create_user_and_budget_and_sign_in().await;
        let unauth_user_access_token = created_unauth_user_and_budget
            .token_pair
            .access_token
            .clone();

        let entry0 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(400_000_000..600_000_000)),
            name: Some("Test Entry 0 for user".to_string()),
            category: Some(0),
            note: Some(String::from("This is a little note")),
        };

        let entry1 = InputEntry {
            budget_id: created_budget.id,
            amount_cents: rand::thread_rng().gen_range(90..=120000),
            date: SystemTime::UNIX_EPOCH
                + Duration::from_secs(rand::thread_rng().gen_range(900_000_000..1_000_000_000)),
            name: None,
            category: None,
            note: None,
        };

        let created_entries = vec![entry0.clone(), entry1.clone()];

        let entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[0])
            .to_request();

        test::call_service(&app, entry0_req).await;

        let entry1_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .set_json(&created_entries[1])
            .to_request();

        test::call_service(&app, entry1_req).await;

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let unauth_get_req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {unauth_user_access_token}"),
            ))
            .to_request();

        let unauth_get_res = test::call_service(&app, unauth_get_req).await;
        assert_eq!(unauth_get_res.status(), http::StatusCode::NOT_FOUND);

        let unauth_get_res_body =
            String::from_utf8(actix_web::test::read_body(unauth_get_res).await.to_vec()).unwrap();
        let _unauth_get_parsed_body =
            serde_json::from_str::<OutputBudget>(unauth_get_res_body.as_str()).unwrap_err();

        let unauth_entry0_req = test::TestRequest::post()
            .uri("/api/budget/add_entry")
            .insert_header(("content-type", "application/json"))
            .insert_header((
                "authorization",
                format!("bearer {unauth_user_access_token}"),
            ))
            .set_json(&created_entries[0])
            .to_request();

        let unauth_entry0_res = test::call_service(&app, unauth_entry0_req).await;
        assert_eq!(unauth_entry0_res.status(), http::StatusCode::NOT_FOUND);

        // Make sure the created budget hasn't changed

        let input_budget_id = InputBudgetId {
            budget_id: created_budget.id,
        };

        let req = test::TestRequest::get()
            .uri(&format!(
                "/api/budget/get?budget_id={}",
                input_budget_id.budget_id
            ))
            .insert_header(("content-type", "application/json"))
            .insert_header(("authorization", format!("bearer {access_token}")))
            .to_request();

        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res_body = String::from_utf8(actix_web::test::read_body(res).await.to_vec()).unwrap();
        let budget = serde_json::from_str::<OutputBudget>(res_body.as_str()).unwrap();

        assert_eq!(budget.id, created_budget.id);
        assert_eq!(budget.is_private, created_budget.is_private);
        assert_eq!(budget.is_deleted, created_budget.is_deleted);
        assert_eq!(budget.name, created_budget.name);
        assert_eq!(budget.description, created_budget.description);
        assert_eq!(budget.start_date, created_budget.start_date);
        assert_eq!(budget.end_date, created_budget.end_date);

        assert!(budget.latest_entry_time > created_budget.latest_entry_time);

        assert_eq!(budget.modified_timestamp, created_budget.modified_timestamp);
        assert_eq!(budget.created_timestamp, created_budget.created_timestamp);

        assert!(!budget.categories.is_empty());
        assert_eq!(budget.categories.len(), created_budget.categories.len());

        for i in 0..budget_categories.len() {
            let fetched_cat = &budget.categories[i];
            let created_cat = &created_budget.categories[i];

            assert_eq!(fetched_cat.pk, created_cat.pk);
            assert_eq!(fetched_cat.budget_id, created_cat.budget_id);
            assert_eq!(fetched_cat.id, created_cat.id);
            assert_eq!(fetched_cat.name, created_cat.name);
            assert_eq!(fetched_cat.limit_cents, created_cat.limit_cents);
            assert_eq!(fetched_cat.color, created_cat.color);
        }

        for (i, created_entry) in created_entries.iter().enumerate() {
            assert_eq!(budget.entries[i].amount_cents, created_entry.amount_cents);
            assert_eq!(budget.entries[i].date, created_entry.date);
            assert_eq!(budget.entries[i].name, created_entry.name);
            assert_eq!(budget.entries[i].category, created_entry.category);
            assert_eq!(budget.entries[i].note, created_entry.note);
        }
    }
}
