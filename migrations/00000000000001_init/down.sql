-- This file should undo anything in `up.sql`

ALTER TABLE blacklisted_tokens DROP CONSTRAINT user_key;
ALTER TABLE budget_comments DROP CONSTRAINT user_key;
ALTER TABLE budget_comments DROP CONSTRAINT budget_key;
ALTER TABLE budget_comment_reactions DROP CONSTRAINT user_key;
ALTER TABLE budget_comment_reactions DROP CONSTRAINT comment_key;
ALTER TABLE budget_share_events DROP CONSTRAINT recipient_key;
ALTER TABLE budget_share_events DROP CONSTRAINT sender_key;
ALTER TABLE budget_share_events DROP CONSTRAINT budget_key;
ALTER TABLE categories DROP CONSTRAINT budget_key;
ALTER TABLE entries DROP CONSTRAINT user_key;
ALTER TABLE entries DROP CONSTRAINT budget_key;
ALTER TABLE entry_comments DROP CONSTRAINT user_key;
ALTER TABLE entry_comments DROP CONSTRAINT entry_key;
ALTER TABLE entry_comment_reactions DROP CONSTRAINT user_key;
ALTER TABLE entry_comment_reactions DROP CONSTRAINT comment_key;
ALTER TABLE otp_attempts DROP CONSTRAINT user_key;
ALTER TABLE password_attempts DROP CONSTRAINT user_key;
ALTER TABLE user_notifications DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT user_key;
ALTER TABLE user_budgets DROP CONSTRAINT budget_key;
ALTER TABLE user_budgets DROP CONSTRAINT ub_only_one_association;

DROP TABLE blacklisted_tokens;
DROP TABLE budgets;
DROP TABLE budget_comments;
DROP TABLE budget_comment_reactions;
DROP TABLE budget_share_events;
DROP TABLE categories;
DROP TABLE entries;
DROP TABLE entry_comments;
DROP TABLE entry_comment_reactions;
DROP TABLE otp_attempts;
DROP TABLE password_attempts;
DROP TABLE users;
DROP TABLE user_notifications;

DROP TABLE user_budgets;
