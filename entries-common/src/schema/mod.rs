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
        recipient_user_email -> Text,
        sender_public_key -> Bytea,
        encryption_key_encrypted -> Bytea,
        budget_accept_private_key_encrypted -> Bytea,
        budget_info_encrypted -> Bytea,
        sender_info_encrypted -> Bytea,
        budget_accept_key_info_encrypted -> Bytea,
        budget_accept_key_id_encrypted -> Bytea,
        share_info_symmetric_key_encrypted -> Bytea,
        recipient_public_key_id_used_by_sender -> Uuid,
        recipient_public_key_id_used_by_server -> Uuid,
        created_unix_timestamp_intdiv_five_million -> Int2,
    }
}

diesel::table! {
    budgets (id) {
        id -> Uuid,
        encrypted_blob -> Bytea,
        version_nonce -> Int8,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    categories (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Bytea,
        version_nonce -> Int8,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    entries (id) {
        id -> Uuid,
        budget_id -> Uuid,
        category_id -> Nullable<Uuid>,
        encrypted_blob -> Bytea,
        version_nonce -> Int8,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    job_registry (job_name) {
        job_name -> Text,
        last_run_timestamp -> Timestamp,
    }
}

diesel::table! {
    signin_nonces (user_email) {
        user_email -> Text,
        nonce -> Int4,
    }
}

diesel::table! {
    user_backup_codes (user_id, code) {
        user_id -> Uuid,
        #[max_length = 12]
        code -> Bpchar,
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
    user_deletion_requests (user_id) {
        user_id -> Uuid,
        ready_for_deletion_time -> Timestamp,
    }
}

diesel::table! {
    user_keystores (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Bytea,
        version_nonce -> Int8,
    }
}

diesel::table! {
    user_otps (user_email) {
        user_email -> Text,
        #[max_length = 8]
        otp -> Bpchar,
        expiration -> Timestamp,
    }
}

diesel::table! {
    user_preferences (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Bytea,
        version_nonce -> Int8,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Text,
        is_verified -> Bool,
        public_key_id -> Uuid,
        public_key -> Bytea,
        created_timestamp -> Timestamp,
        auth_string_hash -> Text,
        auth_string_hash_salt -> Bytea,
        auth_string_hash_mem_cost_kib -> Int4,
        auth_string_hash_threads -> Int4,
        auth_string_hash_iterations -> Int4,
        password_encryption_key_salt -> Bytea,
        password_encryption_key_mem_cost_kib -> Int4,
        password_encryption_key_threads -> Int4,
        password_encryption_key_iterations -> Int4,
        recovery_key_hash_salt_for_encryption -> Bytea,
        recovery_key_hash_salt_for_recovery_auth -> Bytea,
        recovery_key_hash_mem_cost_kib -> Int4,
        recovery_key_hash_threads -> Int4,
        recovery_key_hash_iterations -> Int4,
        recovery_key_auth_hash_rehashed_with_auth_string_params -> Text,
        encryption_key_encrypted_with_password -> Bytea,
        encryption_key_encrypted_with_recovery_key -> Bytea,
    }
}

diesel::joinable!(budget_accept_keys -> budgets (budget_id));
diesel::joinable!(budget_access_keys -> budgets (budget_id));
diesel::joinable!(categories -> budgets (budget_id));
diesel::joinable!(entries -> budgets (budget_id));
diesel::joinable!(entries -> categories (category_id));
diesel::joinable!(user_backup_codes -> users (user_id));
diesel::joinable!(user_deletion_request_budget_keys -> users (user_id));
diesel::joinable!(user_deletion_requests -> users (user_id));
diesel::joinable!(user_keystores -> users (user_id));
diesel::joinable!(user_preferences -> users (user_id));

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
    user_backup_codes,
    user_deletion_request_budget_keys,
    user_deletion_requests,
    user_keystores,
    user_otps,
    user_preferences,
    users,
);
