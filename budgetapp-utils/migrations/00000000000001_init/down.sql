-- This file should undo anything in `up.sql`

ALTER TABLE blacklisted_tokens DROP CONSTRAINT user_key;
ALTER TABLE buddy_relationships DROP CONSTRAINT user1_key;
ALTER TABLE buddy_relationships DROP CONSTRAINT user2_key;
ALTER TABLE buddy_requests DROP CONSTRAINT recipient_key;
ALTER TABLE buddy_requests DROP CONSTRAINT sender_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT recipient_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT sender_key;
ALTER TABLE budget_share_invites DROP CONSTRAINT budget_key;
ALTER TABLE categories DROP CONSTRAINT budget_key;
ALTER TABLE entries DROP CONSTRAINT user_key;
ALTER TABLE entries DROP CONSTRAINT category_key;
ALTER TABLE entries DROP CONSTRAINT budget_key;
ALTER TABLE otp_attempts DROP CONSTRAINT user_key;
ALTER TABLE password_attempts DROP CONSTRAINT user_key;
ALTER TABLE user_notifications DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT budget_key;

DROP TABLE blacklisted_tokens;
DROP TABLE buddy_relationships;
DROP TABLE buddy_requests;
DROP TABLE budgets;
DROP TABLE budget_share_invites;
DROP TABLE categories;
DROP TABLE entries;
DROP TABLE otp_attempts;
DROP TABLE password_attempts;
DROP TABLE users;
DROP TABLE user_deletion_requests;
DROP TABLE user_tombstones;
DROP TABLE user_notifications;

DROP TABLE user_budgets;
