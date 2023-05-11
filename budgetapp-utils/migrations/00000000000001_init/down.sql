-- This file should undo everything in `up.sql`

ALTER TABLE authorization_attempts DROP CONSTRAINT user_key;
ALTER TABLE budget_accept_keys DROP CONSTRAINT budget_key;
ALTER TABLE budget_access_keys DROP CONSTRAINT budget_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT recipient_key;
ALTER TABLE categories DROP CONSTRAINT budget_key;
ALTER TABLE entries DROP CONSTRAINT budget_key;
ALTER TABLE otp_attempts DROP CONSTRAINT user_key;
ALTER TABLE signin_nonces DROP CONSTRAINT user_key;
ALTER TABLE user_lookup_attempts DROP CONSTRAINT user_key;
ALTER TABLE user_deletion_requests DROP CONSTRAINT user_key;
ALTER TABLE user_deletion_request_budget_keys DROP CONSTRAINT user_key;
ALTER TABLE user_deletion_request_budget_keys DROP CONSTRAINT key_key;
ALTER TABLE user_keystores DROP CONSTRAINT user_key;
ALTER TABLE user_preferences DROP CONSTRAINT user_key;
ALTER TABLE user_security_data DROP CONSTRAINT user_key;

DROP TABLE authorization_attempts;
DROP TABLE blacklisted_tokens;
DROP TABLE budgets;
DROP TABLE budget_accept_keys;
DROP TABLE budget_access_keys;
DROP TABLE budget_share_invites;
DROP TABLE categories;
DROP TABLE entries;
DROP TABLE job_registry;
DROP TABLE otp_attempts;
DROP TABLE signin_nonces;
DROP TABLE user_lookup_attempts;
DROP TABLE users;
DROP TABLE user_deletion_requests;
DROP TABLE user_deletion_request_budget_keys;
DROP TABLE user_keystores;
DROP TABLE user_preferences;
DROP TABLE user_security_data;
