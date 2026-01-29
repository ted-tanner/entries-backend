-- This file should undo everything in `up.sql`

DROP TABLE IF EXISTS container_accept_keys CASCADE;
DROP TABLE IF EXISTS container_access_keys CASCADE;
DROP TABLE IF EXISTS container_share_invites CASCADE;
DROP TABLE IF EXISTS categories CASCADE;
DROP TABLE IF EXISTS entries CASCADE;

DROP TABLE IF EXISTS signin_nonces CASCADE;
DROP TABLE IF EXISTS user_backup_codes CASCADE;
DROP TABLE IF EXISTS user_deletion_request_container_keys CASCADE;
DROP TABLE IF EXISTS user_deletion_requests CASCADE;
DROP TABLE IF EXISTS user_flags CASCADE;
DROP TABLE IF EXISTS user_keystores CASCADE;
DROP TABLE IF EXISTS user_otps CASCADE;
DROP TABLE IF EXISTS user_preferences CASCADE;

DROP TABLE IF EXISTS users CASCADE;

DROP TABLE IF EXISTS job_registry CASCADE;
DROP TABLE IF EXISTS containers CASCADE;
DROP TABLE IF EXISTS blacklisted_tokens CASCADE;
