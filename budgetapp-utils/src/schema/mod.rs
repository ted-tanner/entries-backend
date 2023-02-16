table! {
    authorization_attempts (user_id) {
        user_id -> Uuid,
        attempt_count -> Int2,
        expiration_time -> Timestamp,
    }
}

table! {
    blacklisted_tokens (token) {
        token -> Varchar,
        user_id -> Uuid,
        token_expiration_time -> Timestamp,
    }
}

table! {
    buddy_relationships (user1_id, user2_id) {
        user1_id -> Uuid,
        user2_id -> Uuid,
    }
}

table! {
    buddy_requests (id) {
        id -> Uuid,
        recipient_user_id -> Uuid,
        sender_user_id -> Uuid,
        sender_name_encrypted -> Nullable<Text>,
    }
}

table! {
    budget_share_invites (id) {
        id -> Uuid,
        recipient_user_id -> Uuid,
        sender_user_id -> Uuid,
        budget_id -> Uuid,
        budget_name_encrypted -> Text,
        sender_name_encrypted -> Nullable<Text>,
        encryption_key_encrypted -> Text,
        read_only -> Bool,
    }
}

table! {
    budgets (id) {
        id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

table! {
    categories (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

table! {
    entries (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

table! {
    otp_attempts (user_id) {
        user_id -> Uuid,
        attempt_count -> Int2,
        expiration_time -> Timestamp,
    }
}

table! {
    signin_nonces (user_email) {
        user_email -> Varchar,
        nonce -> Int4,
    }
}

table! {
    tombstones (item_id, related_user_id) {
        item_id -> Uuid,
        related_user_id -> Uuid,
        origin_table -> Varchar,
        deletion_timestamp -> Timestamp,
    }
}

table! {
    user_budgets (user_id, budget_id) {
        user_id -> Uuid,
        budget_id -> Uuid,
        encryption_key_encrypted -> Text,
        encryption_key_is_encrypted_with_aes_not_rsa -> Bool,
        read_only -> Bool,
        modified_timestamp -> Timestamp,
    }
}

table! {
    user_deletion_requests (user_id) {
        user_id -> Uuid,
        deletion_request_time -> Timestamp,
        ready_for_deletion_time -> Timestamp,
    }
}

table! {
    user_preferences (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

table! {
    user_security_data (user_id) {
        user_id -> Uuid,
        auth_string_hash -> Text,
        auth_string_salt -> Text,
        auth_string_iters -> Int4,
        password_encryption_salt -> Text,
        password_encryption_iters -> Int4,
        recovery_key_salt -> Text,
        recovery_key_iters -> Int4,
        encryption_key_user_password_encrypted -> Text,
        encryption_key_recovery_key_encrypted -> Text,
        public_rsa_key -> Text,
        private_rsa_key_encrypted -> Text,
        rsa_key_created_timestamp -> Timestamp,
        last_token_refresh_timestamp -> Timestamp,
        modified_timestamp -> Timestamp,
    }
}

table! {
    user_tombstones (user_id) {
        user_id -> Uuid,
        deletion_timestamp -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Uuid,
        email -> Varchar,
        is_verified -> Bool,
        created_timestamp -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    authorization_attempts,
    blacklisted_tokens,
    buddy_relationships,
    buddy_requests,
    budget_share_invites,
    budgets,
    categories,
    entries,
    otp_attempts,
    signin_nonces,
    tombstones,
    user_budgets,
    user_deletion_requests,
    user_preferences,
    user_security_data,
    user_tombstones,
    users,
);
