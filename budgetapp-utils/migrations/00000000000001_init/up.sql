CREATE TABLE blacklisted_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(800) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    token_expiration_time BIGINT NOT NULL
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
    is_shared BOOLEAN NOT NULL,
    is_private BOOLEAN NOT NULL,
    is_deleted BOOLEAN NOT NULL,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    start_date DATE NOT NULL,
    end_date DATE NOT NULL CHECK(end_date >= start_date),

    latest_entry_time TIMESTAMP NOT NULL,
    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE budget_comments (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,
    user_id UUID NOT NULL,

    is_deleted BOOLEAN NOT NULL,
    is_current BOOLEAN NOT NULL,

    text TEXT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE budget_comment_reactions (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    comment_id UUID NOT NULL,
    user_id UUID NOT NULL,

    reaction SMALLINT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE budget_share_events (
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
    pk SERIAL NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,

    is_deleted BOOLEAN NOT NULL,

    id SMALLINT NOT NULL,
    name VARCHAR(120) NOT NULL,
    limit_cents BIGINT NOT NULL,
    color VARCHAR(9) NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entries (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,
    user_id UUID NOT NULL,
    
    is_deleted BOOLEAN NOT NULL,

    amount_cents BIGINT NOT NULL,
    date DATE NOT NULL,
    name VARCHAR(120),
    category SMALLINT,
    note TEXT,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entry_comments (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    entry_id UUID NOT NULL,
    user_id UUID NOT NULL,

    is_deleted BOOLEAN NOT NULL,
    is_current BOOLEAN NOT NULL,

    text TEXT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE entry_comment_reactions (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    comment_id UUID NOT NULL,
    user_id UUID NOT NULL,

    reaction SMALLINT NOT NULL,

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE otp_attempts (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    attempt_count SMALLINT NOT NULL
);

CREATE TABLE password_attempts (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    attempt_count SMALLINT NOT NULL
);

CREATE TABLE users (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL,

    is_premium BOOLEAN NOT NULL,
    premium_expiration DATE,

    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    date_of_birth DATE NOT NULL,
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
ALTER TABLE budget_comments ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_comments ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE budget_comment_reactions ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_comment_reactions ADD CONSTRAINT comment_key FOREIGN KEY(comment_id) REFERENCES budget_comments(id) ON DELETE CASCADE;
ALTER TABLE budget_share_events ADD CONSTRAINT recipient_key FOREIGN KEY(recipient_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_share_events ADD CONSTRAINT sender_key FOREIGN KEY(sender_user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_share_events ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE categories ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE entry_comments ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entry_comments ADD CONSTRAINT entry_key FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE;
ALTER TABLE entry_comment_reactions ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entry_comment_reactions ADD CONSTRAINT comment_key FOREIGN KEY(comment_id) REFERENCES entry_comments(id) ON DELETE CASCADE;
ALTER TABLE otp_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE password_attempts ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT ub_only_one_association UNIQUE (user_id, budget_id);
ALTER TABLE user_notifications ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;

