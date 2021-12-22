-- Your SQL goes here

CREATE TABLE blacklisted_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    token_expiration_epoch BIGINT NOT NULL
);

CREATE TABLE budgets (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    is_shared BOOLEAN NOT NULL,
    is_private BOOLEAN NOT NULL,
    is_deleted BOOLEAN NOT NULL,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

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

CREATE TABLE entries (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    budget_id UUID NOT NULL,
    user_id UUID NOT NULL,
    
    is_deleted BOOLEAN NOT NULL,

    date DATE NOT NULL,
    amount DECIMAL NOT NULL,
    category SMALLINT NOT NULL,
    note TEXT NOT NULL,

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

CREATE TABLE user_notifications (
    id UUID UNIQUE NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL,

    is_unread BOOLEAN NOT NULL, -- Hasn't been seen
    is_pristine BOOLEAN NOT NULL, -- Hasn't been tapped on
    is_deleted BOOLEAN NOT NULL,

    notification_type SMALLINT NOT NULL,
    alt_title VARCHAR(255) NOT NULL,
    alt_message VARCHAR(255) NOT NULL,

    -- Can hold things like associated user, budget, or comment IDs
    associated_data TEXT,
    -- Be sure to check to make sure the data the IDs pertain to still exist!

    modified_timestamp TIMESTAMP NOT NULL,
    created_timestamp TIMESTAMP NOT NULL
);

-- Foreign keys

ALTER TABLE blacklisted_tokens ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_comments ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_comments ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE budget_comment_reactions ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE budget_comment_reactions ADD CONSTRAINT comment_key FOREIGN KEY(comment_id) REFERENCES budget_comments(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entries ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE entry_comments ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entry_comments ADD CONSTRAINT entry_key FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE;
ALTER TABLE entry_comment_reactions ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE entry_comment_reactions ADD CONSTRAINT comment_key FOREIGN KEY(comment_id) REFERENCES entry_comments(id) ON DELETE CASCADE;
ALTER TABLE user_notifications ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Many-to-many relational tables

CREATE TABLE user_budgets (
    id SERIAL PRIMARY KEY,
    created_timestamp TIMESTAMP NOT NULL,
    user_id UUID NOT NULL,
    budget_id UUID NOT NULL
);

ALTER TABLE user_budgets ADD CONSTRAINT user_key FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT budget_key FOREIGN KEY(budget_id) REFERENCES budgets(id) ON DELETE CASCADE;
ALTER TABLE user_budgets ADD CONSTRAINT ub_only_one_association UNIQUE (user_id, budget_id);
