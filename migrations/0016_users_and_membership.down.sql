-- Rollback for 0016.
--
-- Dropped in dependency order: project_members references users, so it goes
-- first. The trigger goes with its table.
--
-- This DESTROYS every account and every project grant. There is no way to
-- reverse it: the password hashes are gone, and rolling forward again produces
-- an empty users table that nobody can sign in to. A deployment rolling this
-- back is choosing to go back to token-only authentication, which is a
-- decision rather than an accident, and the API's own startup will refuse the
-- resulting configuration if it still expects users.
--
-- audit_logs is deliberately untouched. Entries written with actor_kind =
-- 'user' stay exactly as they are: they record what happened, and a person
-- ceasing to have a row here does not make the record of their action untrue.
-- That is the same reasoning ADR 028 applied to a deleted project.

DROP TRIGGER IF EXISTS users_set_updated_at ON users;

DROP INDEX IF EXISTS project_members_project_id_idx;
DROP TABLE IF EXISTS project_members;

DROP INDEX IF EXISTS users_email_lower_key;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS user_role;
