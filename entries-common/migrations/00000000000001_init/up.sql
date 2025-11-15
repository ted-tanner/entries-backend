CREATE TABLE users (
    id UUID PRIMARY KEY,

    email TEXT UNIQUE NOT NULL,
    is_verified BOOLEAN NOT NULL,

    public_key_id UUID NOT NULL,
    public_key BYTEA NOT NULL,

    created_timestamp TIMESTAMP NOT NULL,

    auth_string_hash TEXT NOT NULL,

    auth_string_hash_salt BYTEA NOT NULL,
    auth_string_hash_mem_cost_kib INT NOT NULL,
    auth_string_hash_threads INT NOT NULL,
    auth_string_hash_iterations INT NOT NULL,

    password_encryption_key_salt BYTEA NOT NULL,
    password_encryption_key_mem_cost_kib INT NOT NULL,
    password_encryption_key_threads INT NOT NULL,
    password_encryption_key_iterations INT NOT NULL,

    -- Recovery key gets hashed on the client twice with different salts. One hash is used
    -- to encrypt the account encryption key so it can be recovered. This hash is NOT sent
    -- to the server (but the encryption key it encrypts is). The other hash is used as an
    -- auth string to authenticate with the server in the recovery flow. This hash IS sent
    -- to the server and the server then rehashes it for storage using the same parameters
    -- used to hash the auth string (but with a different salt).
    recovery_key_hash_salt_for_encryption BYTEA NOT NULL,
    recovery_key_hash_salt_for_recovery_auth BYTEA NOT NULL,
    recovery_key_hash_mem_cost_kib INT NOT NULL,
    recovery_key_hash_threads INT NOT NULL,
    recovery_key_hash_iterations INT NOT NULL,

    recovery_key_auth_hash_rehashed_with_auth_string_params TEXT NOT NULL,

    encryption_key_encrypted_with_password BYTEA NOT NULL,
    encryption_key_encrypted_with_recovery_key BYTEA NOT NULL,

    CONSTRAINT chk_email_length CHECK (char_length(email) <= 255),
    CONSTRAINT chk_auth_string_hash_length CHECK (char_length(auth_string_hash) <= 128),
    CONSTRAINT chk_recovery_key_auth_hash_rehashed_with_auth_string_params_length CHECK (char_length(recovery_key_auth_hash_rehashed_with_auth_string_params) <= 128),
    CONSTRAINT chk_public_key_size CHECK (octet_length(public_key) <= 1024),
    CONSTRAINT chk_auth_string_hash_salt_size CHECK (octet_length(auth_string_hash_salt) <= 1024),
    CONSTRAINT chk_password_encryption_key_salt_size CHECK (octet_length(password_encryption_key_salt) <= 1024),
    CONSTRAINT chk_recovery_key_hash_salt_for_encryption_size CHECK (octet_length(recovery_key_hash_salt_for_encryption) <= 1024),
    CONSTRAINT chk_recovery_key_hash_salt_for_recovery_auth_size CHECK (octet_length(recovery_key_hash_salt_for_recovery_auth) <= 1024),
    CONSTRAINT chk_encryption_key_encrypted_with_password_size CHECK (octet_length(encryption_key_encrypted_with_password) <= 4096),
    CONSTRAINT chk_encryption_key_encrypted_with_recovery_key_size CHECK (octet_length(encryption_key_encrypted_with_recovery_key) <= 4096)
);

CREATE TABLE blacklisted_tokens (
    token_signature BYTEA PRIMARY KEY,
    token_expiration TIMESTAMP NOT NULL,
    
    CONSTRAINT chk_token_signature_size CHECK (octet_length(token_signature) <= 1024)
);

CREATE INDEX idx_blacklisted_tokens_token_signature ON blacklisted_tokens(token_signature);

CREATE TABLE containers (
    id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    version_nonce BIGINT NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,
    
    CONSTRAINT chk_containers_encrypted_blob_size CHECK (octet_length(encrypted_blob) <= 104857600)
);

-- These accept keys allow the server to verify that the user with the private key has
-- permission to join a container. Because this table purposefully doesn't store an invitation ID,
-- a user can specify the wrong accept key when accepting a container share. However, they are
-- limited to accepting their OWN invitations as the email address in their auth token must
-- match what is recorded with the invitation and only their public RSA key can decrypt the
-- container encryption key.
CREATE TABLE container_accept_keys (
    key_id UUID UNIQUE NOT NULL,
    container_id UUID NOT NULL,

    public_key BYTEA NOT NULL, -- Ed25519

    expiration TIMESTAMP NOT NULL,
    read_only BOOLEAN NOT NULL,

    PRIMARY KEY (key_id, container_id),
    CONSTRAINT fk_container_accept_keys_container_key FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE,
    CONSTRAINT chk_container_accept_keys_public_key_size CHECK (octet_length(public_key) <= 1024)
);

CREATE INDEX idx_container_accept_keys_container_id ON container_accept_keys(container_id);
CREATE INDEX idx_container_accept_keys_key_id ON container_accept_keys(key_id);

CREATE TABLE container_access_keys (
    key_id UUID UNIQUE NOT NULL,
    container_id UUID NOT NULL,
    public_key BYTEA NOT NULL, -- Ed25519
    read_only BOOLEAN NOT NULL,

    PRIMARY KEY (key_id, container_id),
    CONSTRAINT fk_container_access_keys_container_key FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE,
    CONSTRAINT chk_container_access_keys_public_key_size CHECK (octet_length(public_key) <= 1024)
);

CREATE INDEX idx_container_access_keys_container_id ON container_access_keys(container_id);

CREATE TABLE container_share_invites (
    id UUID PRIMARY KEY,

    recipient_user_email TEXT NOT NULL,
    -- The sender can sign a token to prove to the server that they are authorized to
    -- retract/delete a container_share_invite
    sender_public_key BYTEA NOT NULL, -- Ed25519

    -- Encrypted with recipient's public key. This should never get sent to the recipient user
    -- until the invite has been accepted
    encryption_key_encrypted BYTEA NOT NULL,
    -- The private key the recipient can use to certify they are able to accept the invitation
    -- and join the container. Generated by the server, encrypted with recipient's public key.
    -- The corresponding public key is in the container_accept_keys table.
    --
    -- The server could verify the recipient with their auth token without the user needing to
    -- sign a challenge using this private key. However, the use of the private key allows the
    -- server to avoid storing the container_id together with the invitation.
    container_accept_private_key_encrypted BYTEA NOT NULL,

    -- Container info includes the container ID, container name, etc.
    container_info_encrypted BYTEA NOT NULL,
    -- Sender info includes the sender's name and email address
    sender_info_encrypted BYTEA NOT NULL,
    -- Information about the container_accept_private_key, such as its expiration, whether it is
    -- read-only, etc
    container_accept_key_info_encrypted BYTEA NOT NULL,
    -- The server generates this and encrypts it with with the recipient's public RSA key so
    -- the server can forget about the association.
    container_accept_key_id_encrypted BYTEA NOT NULL,
    -- The symmetric key that is used to encrypt the *_info_encrypted fields above, encrypted
    -- with the recipient's public key. This should be sent to the user even *before* the user
    -- accepts the invitation (the user needs to decrypt the info fields)
    share_info_symmetric_key_encrypted BYTEA NOT NULL,

    -- ID of the invite recipient's public RSA key the sender used to encrypt the symmetric key
    -- and other info about the container and sender
    recipient_public_key_id_used_by_sender UUID NOT NULL,
    -- ID of the invite recipient's public RSA key the server used to encrypt the accept key
    recipient_public_key_id_used_by_server UUID NOT NULL,

    -- The UNIX timestamp of creation, integer-divided by 5 million seconds. The purpose of
    -- storing this is to allow the server to delete 2-month/3-month old invites without being
    -- able to associate them with the expiration time of a container_share_key
    created_unix_timestamp_intdiv_five_million SMALLINT NOT NULL,

    CONSTRAINT fk_container_share_invites_recipient_key FOREIGN KEY(recipient_user_email) REFERENCES users(email) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_recipient_user_email_length CHECK (char_length(recipient_user_email) <= 255),
    CONSTRAINT chk_container_share_invites_sender_public_key_size CHECK (octet_length(sender_public_key) <= 1024),
    CONSTRAINT chk_container_share_invites_encryption_key_encrypted_size CHECK (octet_length(encryption_key_encrypted) <= 4096),
    CONSTRAINT chk_container_share_invites_container_accept_private_key_encrypted_size CHECK (octet_length(container_accept_private_key_encrypted) <= 4096),
    CONSTRAINT chk_container_share_invites_container_info_encrypted_size CHECK (octet_length(container_info_encrypted) <= 1048576),
    CONSTRAINT chk_container_share_invites_sender_info_encrypted_size CHECK (octet_length(sender_info_encrypted) <= 1048576),
    CONSTRAINT chk_container_share_invites_container_accept_key_info_encrypted_size CHECK (octet_length(container_accept_key_info_encrypted) <= 1048576),
    CONSTRAINT chk_container_share_invites_container_accept_key_id_encrypted_size CHECK (octet_length(container_accept_key_id_encrypted) <= 4096),
    CONSTRAINT chk_container_share_invites_share_info_symmetric_key_encrypted_size CHECK (octet_length(share_info_symmetric_key_encrypted) <= 4096)
);

CREATE INDEX idx_container_share_invites_recipient_user_email ON container_share_invites(recipient_user_email);

CREATE TABLE categories (
    id UUID PRIMARY KEY,
    container_id UUID NOT NULL,

    encrypted_blob BYTEA NOT NULL,
    version_nonce BIGINT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    CONSTRAINT fk_categories_container_key FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE,
    CONSTRAINT chk_categories_encrypted_blob_size CHECK (octet_length(encrypted_blob) <= 104857600)
);

CREATE INDEX idx_categories_container_id ON categories(container_id);

CREATE TABLE entries (
    id UUID PRIMARY KEY,
    container_id UUID NOT NULL,

    category_id UUID, -- Intentionally nullable

    encrypted_blob BYTEA NOT NULL,
    version_nonce BIGINT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    CONSTRAINT fk_entries_container_key FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE,
    CONSTRAINT fk_entries_category_key FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL,
    CONSTRAINT chk_entries_encrypted_blob_size CHECK (octet_length(encrypted_blob) <= 104857600)
);

CREATE INDEX idx_entries_container_id ON entries(container_id);
CREATE INDEX idx_entries_category_id ON entries(category_id);

CREATE TABLE job_registry (
    job_name TEXT PRIMARY KEY,
    last_run_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE signin_nonces (
    user_email TEXT PRIMARY KEY,
    nonce INT NOT NULL,

    CONSTRAINT fk_signin_nonces_user_key FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_user_email_length CHECK (char_length(user_email) <= 255)
);

CREATE INDEX idx_signin_nonces_user_email ON signin_nonces(user_email);



CREATE TABLE user_deletion_requests (
    user_id UUID PRIMARY KEY,
    ready_for_deletion_time TIMESTAMP NOT NULL,

    CONSTRAINT fk_user_deletion_requests_user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_deletion_requests_user_id ON user_deletion_requests(user_id);

CREATE TABLE user_deletion_request_container_keys (
    key_id UUID PRIMARY KEY,
    -- Using a users table key rather than user_deletion_requests table key so that these
    -- records may be created before the deletion request (the deletion request doesn't get
    -- created until a user verifies via a link sent to their email). This table may be queried
    -- using data available in an auth token, like the user_id. This table can be related to
    -- the user_deletion_requests table indirectly by joining on user_id for both tables.
    user_id UUID NOT NULL,
    -- This record should be deleted after this time
    delete_me_time TIMESTAMP NOT NULL,

    CONSTRAINT fk_user_deletion_request_container_keys_user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_deletion_request_container_keys_key_key FOREIGN KEY(key_id) REFERENCES container_access_keys(key_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_deletion_request_container_keys_user_id ON user_deletion_request_container_keys(user_id);
CREATE INDEX idx_user_deletion_request_container_keys_delete_me_time ON user_deletion_request_container_keys(delete_me_time);

CREATE TABLE user_keystores (
    user_id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    version_nonce BIGINT NOT NULL,

    CONSTRAINT fk_user_keystores_user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_user_keystores_encrypted_blob_size CHECK (octet_length(encrypted_blob) <= 104857600)
);

CREATE INDEX idx_user_keystores_user_id ON user_keystores(user_id);

CREATE TABLE user_otps (
    user_email TEXT PRIMARY KEY,
    otp CHAR(8) NOT NULL,
    expiration TIMESTAMP NOT NULL,

    CONSTRAINT fk_user_otps_user_key FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_user_email_length CHECK (char_length(user_email) <= 255)
);

CREATE INDEX idx_user_otps_user_email_and_otp ON user_otps(user_email, otp);

CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY,
    encrypted_blob BYTEA NOT NULL,
    version_nonce BIGINT NOT NULL,

    CONSTRAINT fk_user_preferences_user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_user_preferences_encrypted_blob_size CHECK (octet_length(encrypted_blob) <= 104857600)
);

CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
