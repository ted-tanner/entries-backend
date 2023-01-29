CREATE TABLE blacklisted_tokens (
    token VARCHAR(800) PRIMARY KEY,
    user_id UUID NOT NULL,
    token_expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE buddy_relationships (
    user1_id UUID NOT NULL,
    user2_id UUID NOT NULL,
    PRIMARY KEY (user1_id, user2_id)
);

CREATE TABLE buddy_requests (
    id UUID PRIMARY KEY,
    
    recipient_user_id UUID NOT NULL,
    sender_user_id UUID NOT NULL,
    
    sender_name_encrypted TEXT,
    
    UNIQUE (recipient_user_id, sender_user_id),
    CHECK (recipient_user_id != sender_user_id)
);

CREATE INDEX ON buddy_requests USING HASH (recipient_user_id);
CREATE INDEX ON buddy_requests USING HASH (sender_user_id);

CREATE TABLE budgets (
    id UUID PRIMARY KEY,
    encrypted_blob TEXT NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE budget_share_invites (
    id UUID PRIMARY KEY,
    
    recipient_user_id UUID NOT NULL,
    sender_user_id UUID NOT NULL,
    budget_id UUID NOT NULL,

    budget_name_encrypted TEXT NOT NULL,
    sender_name_encrypted TEXT,
    -- This should never get sent to the recipient user until the invite has been accepted
    encryption_key_encrypted TEXT NOT NULL,

    UNIQUE (recipient_user_id, sender_user_id, budget_id),
    CHECK (recipient_user_id != sender_user_id)
);

CREATE INDEX ON budget_share_invites USING HASH (recipient_user_id);
CREATE INDEX ON budget_share_invites USING HASH (sender_user_id);

CREATE TABLE categories (
    id UUID NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,

    encrypted_blob TEXT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entries (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,

    encrypted_blob TEXT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE otp_attempts (
    user_id UUID PRIMARY KEY,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE password_attempts (
    user_id UUID PRIMARY KEY,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE tombstones (
    item_id UUID NOT NULL,
    related_user_id UUID NOT NULL,
    origin_table VARCHAR(40) NOT NULL,
    deletion_timestamp TIMESTAMP NOT NULL,
    PRIMARY KEY (item_id, related_user_id)
);

CREATE INDEX ON tombstones USING HASH (related_user_id);

CREATE TABLE users (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE user_budgets (
    user_id UUID NOT NULL,
    budget_id UUID NOT NULL,

    -- Key should be re-encrypted with AES-256 rather than RSA at earliest possible moment
    -- after exchange
    encryption_key_encrypted TEXT NOT NULL,
    encryption_key_is_encrypted_with_aes_not_rsa BOOLEAN NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, budget_id)
);

CREATE TABLE user_deletion_requests (
    user_id UUID PRIMARY KEY,
    deletion_request_time TIMESTAMP NOT NULL,
    ready_for_deletion_time TIMESTAMP NOT NULL
);

CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY,
    encrypted_blob TEXT NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE user_security_data (
    user_id UUID PRIMARY KEY,

    auth_string_hash TEXT NOT NULL,

    auth_string_salt TEXT NOT NULL,
    auth_string_iters INT NOT NULL,

    password_encryption_salt TEXT NOT NULL,
    password_encryption_iters INT NOT NULL,

    recovery_key_salt TEXT NOT NULL,
    recovery_key_iters INT NOT NULL,

    encryption_key_user_password_encrypted TEXT NOT NULL,
    encryption_key_recovery_key_encrypted TEXT NOT NULL,

    public_rsa_key TEXT NOT NULL,
    private_rsa_key_encrypted TEXT NOT NULL,
    rsa_key_created_timestamp TIMESTAMP NOT NULL,

    last_token_refresh_timestamp TIMESTAMP NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE user_tombstones (
    user_id UUID PRIMARY KEY,
    deletion_timestamp TIMESTAMP NOT NULL
);

-- Foreign keys

ALTER TABLE blacklisted_tokens ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE buddy_relationships ADD CONSTRAINT user1_key FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE buddy_relationships ADD CONSTRAINT user2_key FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE buddy_requests ADD CONSTRAINT recipient_key FOREIGN KEY(recipient_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE buddy_requests ADD CONSTRAINT sender_key FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_share_invites ADD CONSTRAINT recipient_key FOREIGN KEY(recipient_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_share_invites ADD CONSTRAINT sender_key FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_share_invites ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE categories ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE otp_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE password_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE tombstones ADD CONSTRAINT user_key FOREIGN KEY(related_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE user_preferences ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_security_data ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
