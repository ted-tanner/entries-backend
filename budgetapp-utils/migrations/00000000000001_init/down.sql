-- This file should undo everything in `up.sql`

ALTER TABLE blacklisted_tokens DROP CONSTRAINT user_key;
ALTER TABLE buddy_relationships DROP CONSTRAINT user1_key;
ALTER TABLE buddy_relationships DROP CONSTRAINT user2_key;
ALTER TABLE buddy_requests DROP CONSTRAINT recipient_key;
ALTER TABLE buddy_requests DROP CONSTRAINT sender_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT recipient_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT sender_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT budget_key;
ALTER TABLE categories DROP CONSTRAINT budget_key;
ALTER TABLE entries DROP CONSTRAINT budget_key;
ALTER TABLE otp_attempts DROP CONSTRAINT user_key;
ALTER TABLE authorization_attempts DROP CONSTRAINT user_key;
ALTER TABLE tombstones DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT budget_key;
ALTER TABLE user_preferences DROP CONSTRAINT user_key;
ALTER TABLE user_security_data DROP CONSTRAINT user_key;

DROP TABLE blacklisted_tokens;
DROP TABLE buddy_relationships;
DROP TABLE buddy_requests;
DROP TABLE budgets;
DROP TABLE budget_share_invites;
DROP TABLE categories;
DROP TABLE entries;
DROP TABLE otp_attempts;
DROP TABLE authorization_attempts;
DROP TABLE tombstones;
DROP TABLE users;
DROP TABLE user_budgets;
DROP TABLE user_deletion_requests;
DROP TABLE user_preferences;
DROP TABLE user_security_data;
DROP TABLE user_tombstones;
