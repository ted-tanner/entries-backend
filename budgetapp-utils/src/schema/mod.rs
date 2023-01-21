// @generated automatically by Diesel CLI.

diesel::table! {
    blacklisted_tokens (token) {
        token -> Varchar,
        user_id -> Uuid,
        token_expiration_time -> Timestamp,
    }
}

diesel::table! {
    buddy_relationships (user1_id, user2_id) {
        user1_id -> Uuid,
        user2_id -> Uuid,
    }
}

diesel::table! {
    buddy_requests (id) {
        id -> Uuid,
        recipient_user_id -> Uuid,
        sender_user_id -> Uuid,
        accepted -> Bool,
        sender_name_encrypted -> Text,
    }
}

diesel::table! {
    budget_share_invites (id) {
        id -> Uuid,
        recipient_user_id -> Uuid,
        sender_user_id -> Uuid,
        budget_id -> Uuid,
        accepted -> Bool,
        sender_name_encrypted -> Text,
        encryption_key_encrypted -> Text,
    }
}

diesel::table! {
    budgets (id) {
        id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    categories (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    entries (id) {
        id -> Uuid,
        budget_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    otp_attempts (user_id) {
        user_id -> Uuid,
        attempt_count -> Int2,
        expiration_time -> Timestamp,
    }
}

diesel::table! {
    password_attempts (user_id) {
        user_id -> Uuid,
        attempt_count -> Int2,
        expiration_time -> Timestamp,
    }
}

diesel::table! {
    tombstones (item_id, related_user_id) {
        item_id -> Uuid,
        related_user_id -> Uuid,
        deletion_timestamp -> Timestamp,
    }
}

diesel::table! {
    user_budgets (user_id, budget_id) {
        user_id -> Uuid,
        budget_id -> Uuid,
        encryption_key_encrypted -> Text,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    user_deletion_requests (user_id) {
        user_id -> Uuid,
        deletion_request_time -> Timestamp,
        ready_for_deletion_time -> Timestamp,
    }
}

diesel::table! {
    user_preferences (user_id) {
        user_id -> Uuid,
        encrypted_blob -> Text,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
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
        public_rsa_key_created_timestamp -> Text,
        last_token_refresh_timestamp -> Timestamp,
        modified_timestamp -> Timestamp,
    }
}

diesel::table! {
    user_tombstones (user_id) {
        user_id -> Uuid,
        deletion_request_time -> Timestamp,
        deletion_timestamp -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Varchar,
        created_timestamp -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    blacklisted_tokens,
    buddy_relationships,
    buddy_requests,
    budget_share_invites,
    budgets,
    categories,
    entries,
    otp_attempts,
    password_attempts,
    tombstones,
    user_budgets,
    user_deletion_requests,
    user_preferences,
    user_security_data,
    user_tombstones,
    users,
);
