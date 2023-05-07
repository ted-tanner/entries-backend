CREATE TABLE authorization_attempts (
    user_id UUID PRIMARY KEY,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE blacklisted_tokens (
    token_signature BYTEA PRIMARY KEY,
    token_expiration TIMESTAMP NOT NULL
);

CREATE INDEX ON blacklisted_tokens USING HASH (token_signature);

CREATE TABLE budgets (
    id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    encrypted_blob_sha1_hash BYTEA NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL
);

-- These accept keys allow the server to verify that the user with the private key has
-- permission to join a budget. Because this table purposefully doesn't store an invitation ID,
-- a user can specify the wrong accept key when accepting a budget share. However, they are
-- limited to accepting their OWN invitations as the email address in their auth token must
-- match what is recorded with the invitation and only their public RSA key can decrypt the
-- budget encryption key.
CREATE TABLE budget_accept_keys (
    key_id UUID UNIQUE NOT NULL,
    budget_id UUID NOT NULL,

    public_key TEXT NOT NULL, -- Ed25519

    expiration TIMESTAMP NOT NULL,
    read_only BOOLEAN NOT NULL,

    PRIMARY KEY (key_id, budget_id)
);

CREATE INDEX ON budget_accept_keys USING HASH (key_id);

CREATE TABLE budget_access_keys (
    key_id UUID UNIQUE NOT NULL,
    budget_id UUID NOT NULL,
    public_key TEXT NOT NULL, -- Ed25591
    read_only BOOLEAN NOT NULL,
    PRIMARY KEY (key_id, budget_id)
);

CREATE INDEX ON budget_access_keys USING HASH (budget_id);

CREATE TABLE budget_share_invites (
    id UUID PRIMARY KEY,

    recipient_user_email VARCHAR(255) NOT NULL,
    -- The sender can sign a token to prove to the server that they are authorized to
    -- retract/delete a budget_share_invite
    sender_public_key TEXT NOT NULL, -- Ed25519

    -- Encrypted with recipient's public key. This should never get sent to the recipient user
    -- until the invite has been accepted
    encryption_key_encrypted BYTEA NOT NULL,
    -- The private key the recipient can use to certify they are able to accept the invitation
    -- and join the budget. Generated by the sender, encrypted with recipient's public key.
    -- The corresponding public key is in the budget_accept_keys table.
    --
    -- The server could verify the recipient with their auth token without the user needing to
    -- sign a challenge using this private key. However, the use of the private key allows the
    -- server to avoid storing the budget_id together with the invitation.
    budget_accept_private_key_encrypted BYTEA NOT NULL,

    -- Budget info includes the budget ID, budget name, etc.
    budget_info_encrypted BYTEA NOT NULL,
    -- Sender info includes the sender's name and email address
    sender_info_encrypted BYTEA NOT NULL,
    -- Information about the budget_accept_private_key, such as its expiration, whether it is
    -- read-only, etc
    budget_accept_private_key_info_encrypted BYTEA NOT NULL,
    -- The server generates this and encrypts it with with the recipient's public RSA key so
    -- the server can forget about the association.
    budget_accept_private_key_id_encrypted BYTEA NOT NULL,
    -- The symmetric key that is used to encrypt the *_info_encrypted fields above, encrypted
    -- with the recipient's public key. This should be sent to the user even *before* the user
    -- accepts the invitation (the user needs to decrypt the info fields)
    share_info_symmetric_key_encrypted BYTEA NOT NULL,

    -- The UNIX timestamp of creation, integer-divided by 5 million seconds. The purpose of
    -- storing this is to allow the server to delete 2-month/3-month old invites without being
    -- able to associate them with the expiration time of a budget_share_key
    created_unix_timestamp_intdiv_five_million SMALLINT NOT NULL
);

CREATE INDEX ON budget_share_invites USING HASH (recipient_user_email);

CREATE TABLE categories (
    id UUID PRIMARY KEY,
    budget_id UUID NOT NULL,

    encrypted_blob BYTEA NOT NULL,
    encrypted_blob_sha1_hash BYTEA NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entries (
    id UUID PRIMARY KEY,
    budget_id UUID NOT NULL,

    encrypted_blob BYTEA NOT NULL,
    encrypted_blob_sha1_hash BYTEA NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE otp_attempts (
    user_id UUID PRIMARY KEY,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE signin_nonces (
    user_email VARCHAR(255) PRIMARY KEY,
    nonce INT NOT NULL
);

CREATE TABLE user_lookup_attempts (
    user_email VARCHAR(255) PRIMARY KEY,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE users (
    id UUID PRIMARY KEY,

    email VARCHAR(255) UNIQUE NOT NULL,
    is_verified BOOLEAN NOT NULL,

    created_timestamp TIMESTAMP NOT NULL,

    public_key TEXT NOT NULL, -- RSA-4096

    last_token_refresh_timestamp TIMESTAMP NOT NULL,
    last_token_refresh_request_app_version VARCHAR(24) NOT NULL
);

CREATE INDEX ON users USING HASH (email);

CREATE TABLE user_deletion_requests (
    id UUID PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    deletion_request_time TIMESTAMP NOT NULL,
    ready_for_deletion_time TIMESTAMP NOT NULL
);

CREATE INDEX ON user_deletion_requests USING HASH (user_id);

CREATE TABLE user_deletion_request_budget_keys (
    key_id UUID PRIMARY KEY,
    -- Using a users table key rather than user_deletion_requests table key so that this table
    -- may be queried using data available in an auth token, like the user_id. This table can
    -- be related to the user_deletion_requests table indirectly by joining on user_id for
    -- both tables.
    user_id UUID NOT NULL,
    -- This record should be deleted after this time
    delete_me_time TIMESTAMP NOT NULL
);

CREATE INDEX ON user_deletion_request_budget_keys USING HASH (user_id);
CREATE INDEX ON user_deletion_request_budget_keys USING BTREE (delete_me_time);

CREATE TABLE user_keystores (
    user_id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    encrypted_blob_sha1_hash BYTEA NOT NULL
);

CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    encrypted_blob_sha1_hash BYTEA NOT NULL
);

CREATE TABLE user_security_data (
    user_id UUID PRIMARY KEY,

    auth_string_hash TEXT NOT NULL,

    auth_string_salt BYTEA NOT NULL,
    auth_string_memory_cost_kib INT NOT NULL,   
    auth_string_parallelism_factor INT NOT NULL,
    auth_string_iters INT NOT NULL,

    password_encryption_salt BYTEA NOT NULL,
    password_encryption_memory_cost_kib INT NOT NULL,
    password_encryption_parallelism_factor INT NOT NULL,
    password_encryption_iters INT NOT NULL,

    recovery_key_salt BYTEA NOT NULL,
    recovery_key_memory_cost_kib INT NOT NULL,
    recovery_key_parallelism_factor INT NOT NULL,
    recovery_key_iters INT NOT NULL,

    encryption_key_encrypted_with_password BYTEA NOT NULL,
    encryption_key_encrypted_with_recovery_key BYTEA NOT NULL
);

-- Foreign keys

ALTER TABLE authorization_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_accept_keys ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE budget_access_keys ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE budget_share_invites ADD CONSTRAINT recipient_key FOREIGN KEY(recipient_user_email) REFERENCES users(email) ON DELETE CASCADE;
ALTER TABLE categories ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE otp_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE signin_nonces ADD CONSTRAINT user_key FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE;
ALTER TABLE user_lookup_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE;
ALTER TABLE user_deletion_requests ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_deletion_request_budget_keys ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_deletion_request_budget_keys ADD CONSTRAINT key_key FOREIGN KEY(key_id) REFERENCES budget_access_keys(key_id) ON DELETE CASCADE;
ALTER TABLE user_keystores ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_preferences ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_security_data ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
