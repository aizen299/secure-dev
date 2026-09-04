-- 0016_users_and_membership: people, their roles, and which projects they reach.
--
-- §15.5 requires RBAC and project scoping; ADR 033 decided local accounts over
-- an external identity provider. ADR 006 called bearer tokens interim and named
-- this as their replacement.
--
-- Change A gave a CREDENTIAL a scope. This gives a PERSON one, which is the
-- half that lets the audit trail answer "who" instead of "which token".
-- See docs/adr/033-identity-roles-and-project-scoping.md.

-- Three roles, not §15.5's four.
--
-- Developer and Security Engineer differ in which projects they can see, and
-- that is what project_members expresses -- encoding it twice would let the two
-- disagree about the same person.
--
-- `service` is deliberately absent. It is a MACHINE role held only by a token
-- (ADR 023), and putting it here would make it assignable to a row that has a
-- password column. A CI credential is not a junior person.
CREATE TYPE user_role AS ENUM ('viewer', 'engineer', 'admin');

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Case-insensitively unique, because "Ada@example.com" and
    -- "ada@example.com" are one person and two rows would be two identities
    -- with one inbox -- a way to get a second account past an admin's notice.
    email text NOT NULL,

    -- The full Argon2id encoded string: algorithm, version, parameters, salt
    -- and hash. Stored whole rather than in columns so a future parameter
    -- change is a value change and not a migration, and so a row carries the
    -- cost it was hashed at rather than the cost configured today.
    --
    -- Never selected into any response type. The store's read path lists its
    -- columns explicitly for that reason.
    password_hash text NOT NULL,

    display_name text NOT NULL DEFAULT '',
    role user_role NOT NULL DEFAULT 'viewer',

    -- Disabled rather than deleted. §17 requires soft-delete for
    -- security-relevant records, and a person's audit trail must stay readable
    -- after they leave -- which is exactly when it is most likely to be read.
    disabled_at timestamptz,

    -- Observability for the account, not a session store: "when did this
    -- credential last work" is the question an admin asks about a dormant
    -- account, and it needs no session table to answer.
    last_login_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_not_blank CHECK (length(btrim(email)) > 0),
    -- Deliberately loose. Email validation by regex is a well-known way to
    -- reject valid addresses; this catches an obvious mistake and leaves the
    -- rest to whether the person can be reached.
    CONSTRAINT users_email_shape CHECK (position('@' IN email) > 1),
    CONSTRAINT users_password_hash_is_argon2id CHECK (password_hash LIKE '$argon2id$%')
);

-- The uniqueness that matters, expressed once.
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- Membership is the project scope of a person.
--
-- A row here means "this user reaches this project". No row means they do not,
-- which makes the absence of a grant the deny -- the same property auth.Scope's
-- zero value has, expressed in the schema.
--
-- An admin's reach is NOT expressed here. Global access is a property of the
-- role, checked in code, because enumerating every project into this table for
-- an admin would mean a new project silently failing to appear for them.
CREATE TABLE project_members (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, project_id)
);

-- The reverse lookup: who can see this project. An admin auditing access asks
-- it far more often than the primary key's direction serves.
CREATE INDEX project_members_project_id_idx ON project_members (project_id);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- audit_logs.actor is already free text and audit_logs.actor_kind already
-- discriminates 'token_label' from 'system' (0011). Adding 'user' needs no
-- schema change here -- the column was built for this, and ADR 022's append-only
-- triggers stay untouched.
--
-- Nothing is backfilled. Records written before this migration keep
-- 'token_label' and stay truthful about what the system knew when it wrote
-- them; inventing an attribution retroactively would make the log worse than
-- one that admits its limit.
