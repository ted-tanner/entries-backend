// @generated automatically by Diesel CLI.

diesel::table! {
    blacklisted_tokens (token_signature) {
        token_signature -> Bytea,
        token_expiration -> Timestamp,
    }
}

diesel::table! {
    budget_accept_keys (key_id, budget_id) {
        key_id -> Uuid,
        budget_id -> Uuid,
        public_key -> Bytea,
        expiration -> Timestamp,
        read_only -> Bool,
    }
}

diesel::table! {
    budget_access_keys (key_id, budget_id) {
        key_id -> Uuid,
        budget_id -> Uuid,
        public_key -> Bytea,
        read_only -> Bool,
    }
}

diesel::table! {
    budget_share_invites (id) {
        id -> Uuid,
        recipient_user_email -> Varchar,
        sender_public_key -> Bytea,
        encryption_key_encrypted -> Bytea,
        budget_accept_private_key_encrypted -> Bytea,
        budget_info_encrypted -> Bytea,
        sender_info_encrypted -> Bytea,
        budget_accept_key_info_encrypted -> Bytea,
        budget_accept_key_id_encrypted -> Bytea,
        share_info_symmetric_key_encrypted -> Bytea,
        created_unix_timestamp_intdiv_five_million -> Int2,
    }
}

diesel::table! {
    budgets (id) {
        id -> Uuid,
        encrypted_blob -> Bytea,
        encrypted_blob_sha1_hash -> Bytea,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    categories (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Bytea,
        encrypted_blob_sha1_hash -> Bytea,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    entries (id) {
        id -> Uuid,
        budget_id -> Uuid,
        category_id -> Nullable<Uuid>,
        encrypted_blob -> Bytea,
        encrypted_blob_sha1_hash -> Bytea,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    job_registry (job_name) {
        job_name -> Varchar,
        last_run_timestamp -> Timestamp,
    }
}

diesel::table! {
    signin_nonces (user_email) {
        user_email -> Varchar,
        nonce -> Int4,
    }
}

diesel::table! {
    throttleable_attempts (identifier_hash) {
        identifier_hash -> Int8,
        attempt_count -> Int4,
        expiration_timestamp -> Timestamp,
    }
}

diesel::table! {
    user_deletion_request_budget_keys (key_id) {
        key_id -> Uuid,
        user_id -> Uuid,
        delete_me_time -> Timestamp,
    }
}

diesel::table! {
    user_deletion_requests (id) {
        id -> Uuid,
        user_id -> Uuid,
        deletion_request_time -> Timestamp,
        ready_for_deletion_time -> Timestamp,
    }
}

diesel::table! {
    user_keystores (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Bytea,
        encrypted_blob_sha1_hash -> Bytea,
    }
}

diesel::table! {
    user_preferences (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Bytea,
        encrypted_blob_sha1_hash -> Bytea,
    }
}

diesel::table! {
    user_security_data (user_id) {
        user_id -> Uuid,
        auth_string_hash -> Text,
        auth_string_salt -> Bytea,
        auth_string_memory_cost_kib -> Int4,
        auth_string_parallelism_factor -> Int4,
        auth_string_iters -> Int4,
        password_encryption_salt -> Bytea,
        password_encryption_memory_cost_kib -> Int4,
        password_encryption_parallelism_factor -> Int4,
        password_encryption_iters -> Int4,
        recovery_key_salt -> Bytea,
        recovery_key_memory_cost_kib -> Int4,
        recovery_key_parallelism_factor -> Int4,
        recovery_key_iters -> Int4,
        encryption_key_encrypted_with_password -> Bytea,
        encryption_key_encrypted_with_recovery_key -> Bytea,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Varchar,
        is_verified -> Bool,
        created_timestamp -> Timestamp,
        public_key -> Bytea,
        last_token_refresh_timestamp -> Timestamp,
        last_token_refresh_request_app_version -> Varchar,
    }
}

diesel::joinable!(entries -> categories (category_id));

diesel::allow_tables_to_appear_in_same_query!(
    blacklisted_tokens,
    budget_accept_keys,
    budget_access_keys,
    budget_share_invites,
    budgets,
    categories,
    entries,
    job_registry,
    signin_nonces,
    throttleable_attempts,
    user_deletion_request_budget_keys,
    user_deletion_requests,
    user_keystores,
    user_preferences,
    user_security_data,
    users,
);
