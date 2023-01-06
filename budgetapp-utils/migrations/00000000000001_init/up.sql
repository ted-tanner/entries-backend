CREATE TABLE blacklisted_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(800) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    token_expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE buddy_relationships (
    id SERIAL PRIMARY KEY,
    created_timestamp TIMESTAMP NOT NULL,
    user1_id UUID NOT NULL,
    user2_id UUID NOT NULL,
    UNIQUE (user1_id, user2_id)
);

CREATE TABLE buddy_requests (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    
    recipient_user_id UUID NOT NULL,
    sender_user_id UUID NOT NULL,
    
    accepted BOOLEAN NOT NULL,
    created_timestamp TIMESTAMP NOT NULL,
    accepted_declined_timestamp TIMESTAMP,
    
    UNIQUE (recipient_user_id, sender_user_id),
    CHECK (recipient_user_id != sender_user_id)
);

CREATE TABLE budgets (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    is_deleted BOOLEAN NOT NULL,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL CHECK(end_date >= start_date),

    latest_entry_time TIMESTAMP NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE budget_share_invites (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    
    recipient_user_id UUID NOT NULL,
    sender_user_id UUID NOT NULL,

    budget_id UUID NOT NULL,
    accepted BOOLEAN NOT NULL,

    created_timestamp TIMESTAMP NOT NULL,
    accepted_declined_timestamp TIMESTAMP,
    
    UNIQUE (recipient_user_id, sender_user_id, budget_id),
    CHECK (recipient_user_id != sender_user_id)
);

CREATE TABLE categories (
    id UUID NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,

    name VARCHAR(120) NOT NULL,
    limit_cents BIGINT NOT NULL,
    color VARCHAR(9) NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entries (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,
    user_id UUID,
    
    is_deleted BOOLEAN NOT NULL,

    amount_cents BIGINT NOT NULL,
    date TIMESTAMP NOT NULL,
    name VARCHAR(120),
    note TEXT,

    category_id UUID,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE otp_attempts (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE password_attempts (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    attempt_count SMALLINT NOT NULL,
    expiration_time TIMESTAMP NOT NULL
);

CREATE TABLE users (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    password_hash TEXT NOT NULL,

    is_premium BOOLEAN NOT NULL,
    premium_expiration TIMESTAMP,

    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    date_of_birth TIMESTAMP NOT NULL,
    currency VARCHAR(3) NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE user_budgets (
    id SERIAL PRIMARY KEY,
    created_timestamp TIMESTAMP NOT NULL,
    user_id UUID NOT NULL,
    budget_id UUID NOT NULL,
    UNIQUE (user_id, budget_id)
);

CREATE TABLE user_deletion_requests (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    deletion_request_time TIMESTAMP NOT NULL,
    ready_for_deletion_time TIMESTAMP NOT NULL
);

CREATE TABLE user_tombstones (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    deletion_request_time TIMESTAMP NOT NULL,
    deletion_time TIMESTAMP NOT NULL
);

CREATE TABLE user_notifications (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL,

    is_unread BOOLEAN NOT NULL, -- Hasn't been seen
    is_pristine BOOLEAN NOT NULL, -- Hasn't been tapped on
    is_deleted BOOLEAN NOT NULL,

    notification_type SMALLINT NOT NULL,
    alt_title VARCHAR(500) NOT NULL,
    alt_message VARCHAR(500) NOT NULL,

    -- Can hold things like associated user, budget, or comment IDs
    associated_data TEXT,
    -- Be sure to check to make sure the data the IDs pertain to still exist!

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
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
ALTER TABLE entries ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE entries ADD CONSTRAINT category_key FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL;
ALTER TABLE otp_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE password_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE user_notifications ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
