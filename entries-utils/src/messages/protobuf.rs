#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UuidV4 {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Category {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "2")]
    pub budget_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "3")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub encrypted_blob_sha1_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub modified_timestamp: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Entry {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "2")]
    pub budget_id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "3")]
    pub category_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "4")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub encrypted_blob_sha1_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "6")]
    pub modified_timestamp: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthStringAndEncryptedPasswordUpdate {
    #[prost(string, tag = "1")]
    pub user_email: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub otp: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "3")]
    pub new_auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "5")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, tag = "6")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, tag = "7")]
    pub auth_string_iters: i32,
    #[prost(bytes = "vec", tag = "8")]
    pub password_encryption_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "9")]
    pub password_encryption_memory_cost_kib: i32,
    #[prost(int32, tag = "10")]
    pub password_encryption_parallelism_factor: i32,
    #[prost(int32, tag = "11")]
    pub password_encryption_iters: i32,
    #[prost(bytes = "vec", tag = "12")]
    pub encrypted_encryption_key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCode {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetAccessTokenList {
    #[prost(string, repeated, tag = "1")]
    pub tokens: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryId {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryUpdate {
    #[prost(message, optional, tag = "1")]
    pub category_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryWithTempId {
    #[prost(int32, tag = "1")]
    pub temp_id: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialPair {
    #[prost(string, tag = "1")]
    pub email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "3")]
    pub nonce: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Email {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedBlobAndCategoryId {
    #[prost(bytes = "vec", tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub category_id: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedBlobUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryAndCategory {
    #[prost(bytes = "vec", tag = "1")]
    pub entry_encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub category_encrypted_blob: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryId {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryUpdate {
    #[prost(message, optional, tag = "1")]
    pub entry_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub category_id: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewBudget {
    #[prost(bytes = "vec", tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub categories: ::prost::alloc::vec::Vec<CategoryWithTempId>,
    #[prost(bytes = "vec", tag = "3")]
    pub user_public_budget_key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewEncryptedBlob {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewUser {
    #[prost(string, tag = "1")]
    pub email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "4")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, tag = "5")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, tag = "6")]
    pub auth_string_iters: i32,
    #[prost(bytes = "vec", tag = "7")]
    pub password_encryption_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "8")]
    pub password_encryption_memory_cost_kib: i32,
    #[prost(int32, tag = "9")]
    pub password_encryption_parallelism_factor: i32,
    #[prost(int32, tag = "10")]
    pub password_encryption_iters: i32,
    #[prost(bytes = "vec", tag = "11")]
    pub recovery_key_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "12")]
    pub recovery_key_memory_cost_kib: i32,
    #[prost(int32, tag = "13")]
    pub recovery_key_parallelism_factor: i32,
    #[prost(int32, tag = "14")]
    pub recovery_key_iters: i32,
    #[prost(bytes = "vec", tag = "15")]
    pub encryption_key_encrypted_with_password: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub encryption_key_encrypted_with_recovery_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub preferences_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "19")]
    pub user_keystore_encrypted: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Otp {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoveryKeyUpdate {
    #[prost(string, tag = "1")]
    pub otp: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub recovery_key_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "3")]
    pub recovery_key_memory_cost_kib: i32,
    #[prost(int32, tag = "4")]
    pub recovery_key_parallelism_factor: i32,
    #[prost(int32, tag = "5")]
    pub recovery_key_iters: i32,
    #[prost(bytes = "vec", tag = "6")]
    pub encrypted_encryption_key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserInvitationToBudget {
    #[prost(string, tag = "1")]
    pub recipient_user_email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub encryption_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub budget_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub sender_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub share_info_symmetric_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub expiration: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(bool, tag = "8")]
    pub read_only: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCodesAndVerificationEmailSent {
    #[prost(bool, tag = "1")]
    pub email_sent: bool,
    #[prost(uint64, tag = "2")]
    pub email_token_lifetime_hours: u64,
    #[prost(string, repeated, tag = "3")]
    pub backup_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCodeList {
    #[prost(string, repeated, tag = "1")]
    pub backup_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Budget {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub modified_timestamp: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, repeated, tag = "4")]
    pub categories: ::prost::alloc::vec::Vec<Category>,
    #[prost(message, repeated, tag = "5")]
    pub entries: ::prost::alloc::vec::Vec<Entry>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetFrame {
    #[prost(message, optional, tag = "1")]
    pub access_key_id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "2")]
    pub id: ::core::option::Option<UuidV4>,
    #[prost(message, repeated, tag = "3")]
    pub category_ids: ::prost::alloc::vec::Vec<BudgetFrameCategory>,
    #[prost(message, optional, tag = "4")]
    pub modified_timestamp: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetFrameCategory {
    #[prost(int32, tag = "1")]
    pub temp_id: i32,
    #[prost(message, optional, tag = "2")]
    pub real_id: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetIdAndEncryptionKey {
    #[prost(message, optional, tag = "1")]
    pub budget_id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "2")]
    pub budget_access_key_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "3")]
    pub encryption_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, tag = "4")]
    pub read_only: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetShareInvite {
    #[prost(message, optional, tag = "1")]
    pub invite_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", tag = "2")]
    pub budget_accept_private_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub budget_accept_private_key_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub budget_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub sender_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub budget_accept_private_key_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub share_info_symmetric_key_encrypted: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryIdAndCategoryId {
    #[prost(message, optional, tag = "1")]
    pub entry_id: ::core::option::Option<UuidV4>,
    #[prost(message, optional, tag = "2")]
    pub category_id: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationId {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<UuidV4>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsUserListedForDeletion {
    #[prost(bool, tag = "1")]
    pub is_listed_for_deletion: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigninNonceAndHashParams {
    #[prost(bytes = "vec", tag = "1")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "2")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, tag = "3")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, tag = "4")]
    pub auth_string_iters: i32,
    #[prost(int32, tag = "5")]
    pub nonce: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigninToken {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenPair {
    #[prost(string, tag = "1")]
    pub access_token: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub refresh_token: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub server_time: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerificationEmailSent {
    #[prost(bool, tag = "1")]
    pub email_sent: bool,
    #[prost(uint64, tag = "2")]
    pub email_token_lifetime_hours: u64,
}
