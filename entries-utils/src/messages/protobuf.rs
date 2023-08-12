use zeroize::Zeroize;

#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Timestamp {
    #[prost(uint64, required, tag = "1")]
    pub secs: u64,
    #[prost(uint32, required, tag = "2")]
    pub nanos: u32,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UuidV4 {
    #[prost(bytes = "vec", required, tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Category {
    #[prost(message, required, tag = "1")]
    pub id: UuidV4,
    #[prost(message, required, tag = "2")]
    pub budget_id: UuidV4,
    #[prost(bytes = "vec", required, tag = "3")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub encrypted_blob_sha1_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag = "5")]
    pub modified_timestamp: Timestamp,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Entry {
    #[prost(message, required, tag = "1")]
    pub id: UuidV4,
    #[prost(message, required, tag = "2")]
    pub budget_id: UuidV4,
    #[prost(message, optional, tag = "3")]
    pub category_id: ::core::option::Option<UuidV4>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "5")]
    pub encrypted_blob_sha1_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag = "6")]
    pub modified_timestamp: Timestamp,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthStringAndEncryptedPasswordUpdate {
    #[prost(string, required, tag = "1")]
    pub user_email: ::prost::alloc::string::String,
    #[prost(string, required, tag = "2")]
    pub otp: ::prost::alloc::string::String,
    #[prost(bytes = "vec", required, tag = "3")]
    pub new_auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "5")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, required, tag = "6")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, required, tag = "7")]
    pub auth_string_iters: i32,
    #[prost(bytes = "vec", required, tag = "8")]
    pub password_encryption_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "9")]
    pub password_encryption_memory_cost_kib: i32,
    #[prost(int32, required, tag = "10")]
    pub password_encryption_parallelism_factor: i32,
    #[prost(int32, required, tag = "11")]
    pub password_encryption_iters: i32,
    #[prost(bytes = "vec", required, tag = "12")]
    pub encrypted_encryption_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCode {
    #[prost(string, required, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetAccessTokenList {
    #[prost(string, repeated, tag = "1")]
    pub tokens: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryId {
    #[prost(message, required, tag = "1")]
    pub value: UuidV4,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryUpdate {
    #[prost(message, required, tag = "1")]
    pub category_id: UuidV4,
    #[prost(bytes = "vec", required, tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryWithTempId {
    #[prost(int32, required, tag = "1")]
    pub temp_id: i32,
    #[prost(bytes = "vec", required, tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialPair {
    #[prost(string, required, tag = "1")]
    pub email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", required, tag = "2")]
    pub auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "3")]
    pub nonce: i32,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedBlobAndCategoryId {
    #[prost(bytes = "vec", required, tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub category_id: ::core::option::Option<UuidV4>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedBlobUpdate {
    #[prost(bytes = "vec", required, tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryAndCategory {
    #[prost(bytes = "vec", required, tag = "1")]
    pub entry_encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub category_encrypted_blob: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryId {
    #[prost(message, required, tag = "1")]
    pub value: UuidV4,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryUpdate {
    #[prost(message, required, tag = "1")]
    pub entry_id: UuidV4,
    #[prost(bytes = "vec", required, tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub expected_previous_data_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub category_id: ::core::option::Option<UuidV4>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewBudget {
    #[prost(bytes = "vec", required, tag = "1")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub categories: ::prost::alloc::vec::Vec<CategoryWithTempId>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub user_public_budget_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewEncryptedBlob {
    #[prost(bytes = "vec", required, tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewUser {
    #[prost(string, required, tag = "1")]
    pub email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", required, tag = "2")]
    pub auth_string: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "4")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, required, tag = "5")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, required, tag = "6")]
    pub auth_string_iters: i32,
    #[prost(bytes = "vec", required, tag = "7")]
    pub password_encryption_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "8")]
    pub password_encryption_memory_cost_kib: i32,
    #[prost(int32, required, tag = "9")]
    pub password_encryption_parallelism_factor: i32,
    #[prost(int32, required, tag = "10")]
    pub password_encryption_iters: i32,
    #[prost(bytes = "vec", required, tag = "11")]
    pub recovery_key_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "12")]
    pub recovery_key_memory_cost_kib: i32,
    #[prost(int32, required, tag = "13")]
    pub recovery_key_parallelism_factor: i32,
    #[prost(int32, required, tag = "14")]
    pub recovery_key_iters: i32,
    #[prost(bytes = "vec", required, tag = "15")]
    pub encryption_key_encrypted_with_password: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "16")]
    pub encryption_key_encrypted_with_recovery_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "17")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "18")]
    pub preferences_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "19")]
    pub user_keystore_encrypted: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Otp {
    #[prost(string, required, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(bytes = "vec", required, tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecoveryKeyUpdate {
    #[prost(string, required, tag = "1")]
    pub otp: ::prost::alloc::string::String,
    #[prost(bytes = "vec", required, tag = "2")]
    pub recovery_key_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "3")]
    pub recovery_key_memory_cost_kib: i32,
    #[prost(int32, required, tag = "4")]
    pub recovery_key_parallelism_factor: i32,
    #[prost(int32, required, tag = "5")]
    pub recovery_key_iters: i32,
    #[prost(bytes = "vec", required, tag = "6")]
    pub encrypted_encryption_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserInvitationToBudget {
    #[prost(string, required, tag = "1")]
    pub recipient_user_email: ::prost::alloc::string::String,
    #[prost(bytes = "vec", required, tag = "2")]
    pub sender_public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub encryption_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub budget_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "5")]
    pub sender_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "6")]
    pub share_info_symmetric_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag = "7")]
    pub expiration: Timestamp,
    #[prost(bool, required, tag = "8")]
    pub read_only: bool,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcceptKeyInfo {
    #[prost(bool, required, tag = "1")]
    pub read_only: bool,
    #[prost(uint64, required, tag = "2")]
    pub expiration: u64,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCodesAndVerificationEmailSent {
    #[prost(bool, required, tag = "1")]
    pub email_sent: bool,
    #[prost(uint64, required, tag = "2")]
    pub email_token_lifetime_hours: u64,
    #[prost(string, repeated, tag = "3")]
    pub backup_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupCodeList {
    #[prost(string, repeated, tag = "1")]
    pub backup_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Budget {
    #[prost(message, required, tag = "1")]
    pub id: UuidV4,
    #[prost(bytes = "vec", required, tag = "2")]
    pub encrypted_blob: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag = "3")]
    pub modified_timestamp: Timestamp,
    #[prost(message, repeated, tag = "4")]
    pub categories: ::prost::alloc::vec::Vec<Category>,
    #[prost(message, repeated, tag = "5")]
    pub entries: ::prost::alloc::vec::Vec<Entry>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetFrame {
    #[prost(message, required, tag = "1")]
    pub access_key_id: UuidV4,
    #[prost(message, required, tag = "2")]
    pub id: UuidV4,
    #[prost(message, repeated, tag = "3")]
    pub category_ids: ::prost::alloc::vec::Vec<BudgetFrameCategory>,
    #[prost(message, required, tag = "4")]
    pub modified_timestamp: Timestamp,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetFrameCategory {
    #[prost(int32, required, tag = "1")]
    pub temp_id: i32,
    #[prost(message, required, tag = "2")]
    pub real_id: UuidV4,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetIdAndEncryptionKey {
    #[prost(message, required, tag = "1")]
    pub budget_id: UuidV4,
    #[prost(message, required, tag = "2")]
    pub budget_access_key_id: UuidV4,
    #[prost(bytes = "vec", required, tag = "3")]
    pub encryption_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bool, required, tag = "4")]
    pub read_only: bool,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetList {
    #[prost(message, repeated, tag = "1")]
    pub budgets: ::prost::alloc::vec::Vec<Budget>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetShareInvite {
    #[prost(message, required, tag = "1")]
    pub id: UuidV4,
    #[prost(bytes = "vec", required, tag = "2")]
    pub budget_accept_key_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub budget_accept_key_id_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "4")]
    pub budget_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "5")]
    pub sender_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "6")]
    pub budget_accept_key_info_encrypted: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", required, tag = "7")]
    pub share_info_symmetric_key_encrypted: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BudgetShareInviteList {
    #[prost(message, repeated, tag = "1")]
    pub invites: ::prost::alloc::vec::Vec<BudgetShareInvite>,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EntryIdAndCategoryId {
    #[prost(message, required, tag = "1")]
    pub entry_id: UuidV4,
    #[prost(message, required, tag = "2")]
    pub category_id: UuidV4,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationId {
    #[prost(message, required, tag = "1")]
    pub value: UuidV4,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IsUserListedForDeletion {
    #[prost(bool, required, tag = "1")]
    pub is_listed_for_deletion: bool,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerErrorResponse {
    #[prost(
        enumeration = "ErrorType",
        required,
        tag = "1",
        default = "InternalError"
    )]
    pub err_type: i32,
    #[prost(string, required, tag = "2")]
    pub err_message: ::prost::alloc::string::String,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigninNonceAndHashParams {
    #[prost(bytes = "vec", required, tag = "1")]
    pub auth_string_salt: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, required, tag = "2")]
    pub auth_string_memory_cost_kib: i32,
    #[prost(int32, required, tag = "3")]
    pub auth_string_parallelism_factor: i32,
    #[prost(int32, required, tag = "4")]
    pub auth_string_iters: i32,
    #[prost(int32, required, tag = "5")]
    pub nonce: i32,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigninToken {
    #[prost(string, required, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenPair {
    #[prost(string, required, tag = "1")]
    pub access_token: ::prost::alloc::string::String,
    #[prost(string, required, tag = "2")]
    pub refresh_token: ::prost::alloc::string::String,
    #[prost(message, required, tag = "3")]
    pub server_time: Timestamp,
}
#[derive(Zeroize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerificationEmailSent {
    #[prost(bool, required, tag = "1")]
    pub email_sent: bool,
    #[prost(uint64, required, tag = "2")]
    pub email_token_lifetime_hours: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorType {
    /// 400
    IncorrectlyFormed = 0,
    InvalidMessage = 1,
    OutOfDate = 2,
    InvalidState = 3,
    MissingHeader = 4,
    ConflictWithExisting = 5,
    /// 401
    IncorrectCredential = 6,
    TokenExpired = 7,
    TokenMissing = 8,
    WrongTokenType = 9,
    /// 403
    UserDisallowed = 10,
    PendingAction = 11,
    IncorrectNonce = 12,
    TooManyAttempts = 13,
    ReadOnlyAccess = 14,
    /// 404
    DoesNotExist = 15,
    ForeignKeyDoesNotExist = 16,
    /// 418
    InputTooLarge = 17,
    /// 500
    InternalError = 18,
}
impl ErrorType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ErrorType::IncorrectlyFormed => "INCORRECTLY_FORMED",
            ErrorType::InvalidMessage => "INVALID_MESSAGE",
            ErrorType::OutOfDate => "OUT_OF_DATE",
            ErrorType::InvalidState => "INVALID_STATE",
            ErrorType::MissingHeader => "MISSING_HEADER",
            ErrorType::ConflictWithExisting => "CONFLICT_WITH_EXISTING",
            ErrorType::IncorrectCredential => "INCORRECT_CREDENTIAL",
            ErrorType::TokenExpired => "TOKEN_EXPIRED",
            ErrorType::TokenMissing => "TOKEN_MISSING",
            ErrorType::WrongTokenType => "WRONG_TOKEN_TYPE",
            ErrorType::UserDisallowed => "USER_DISALLOWED",
            ErrorType::PendingAction => "PENDING_ACTION",
            ErrorType::IncorrectNonce => "INCORRECT_NONCE",
            ErrorType::TooManyAttempts => "TOO_MANY_ATTEMPTS",
            ErrorType::ReadOnlyAccess => "READ_ONLY_ACCESS",
            ErrorType::DoesNotExist => "DOES_NOT_EXIST",
            ErrorType::ForeignKeyDoesNotExist => "FOREIGN_KEY_DOES_NOT_EXIST",
            ErrorType::InputTooLarge => "INPUT_TOO_LARGE",
            ErrorType::InternalError => "INTERNAL_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "INCORRECTLY_FORMED" => Some(Self::IncorrectlyFormed),
            "INVALID_MESSAGE" => Some(Self::InvalidMessage),
            "OUT_OF_DATE" => Some(Self::OutOfDate),
            "INVALID_STATE" => Some(Self::InvalidState),
            "MISSING_HEADER" => Some(Self::MissingHeader),
            "CONFLICT_WITH_EXISTING" => Some(Self::ConflictWithExisting),
            "INCORRECT_CREDENTIAL" => Some(Self::IncorrectCredential),
            "TOKEN_EXPIRED" => Some(Self::TokenExpired),
            "TOKEN_MISSING" => Some(Self::TokenMissing),
            "WRONG_TOKEN_TYPE" => Some(Self::WrongTokenType),
            "USER_DISALLOWED" => Some(Self::UserDisallowed),
            "PENDING_ACTION" => Some(Self::PendingAction),
            "INCORRECT_NONCE" => Some(Self::IncorrectNonce),
            "TOO_MANY_ATTEMPTS" => Some(Self::TooManyAttempts),
            "READ_ONLY_ACCESS" => Some(Self::ReadOnlyAccess),
            "DOES_NOT_EXIST" => Some(Self::DoesNotExist),
            "FOREIGN_KEY_DOES_NOT_EXIST" => Some(Self::ForeignKeyDoesNotExist),
            "INPUT_TOO_LARGE" => Some(Self::InputTooLarge),
            "INTERNAL_ERROR" => Some(Self::InternalError),
            _ => None,
        }
    }
}
