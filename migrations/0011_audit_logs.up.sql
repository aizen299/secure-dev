-- 0011_audit_logs: who changed what, when, and what it was before.
--
-- §15.6 requires this and §17 requires it to be append-only. SecureOps has had
-- audit *logging* since Phase 3a -- a structured line per mutation -- and no
-- audit *log*. That was honest while the mutations were creating projects and
-- enqueuing scans; it stops being honest in Phase 8, because a policy is the
-- control that decides whether insecure code ships. Someone who raises
-- max_critical from 0 to 50 turns the gate off, and "PUT /policy 200" does not
-- record that they did.
--
-- See docs/adr/022-durable-audit-log.md.

CREATE TABLE audit_logs (
    id bigserial PRIMARY KEY,

    -- When the change happened, not when it was written: they are the same
    -- here because the record is written in the change's own transaction.
    occurred_at timestamptz NOT NULL DEFAULT now(),

    -- The actor SecureOps actually has. The interim bearer token labels a
    -- client, not a person (ADR 006), so this is stored as a token label and
    -- named as one. Recording it as a user id would be a more useful-looking
    -- field and a false one.
    actor_kind  text NOT NULL,
    actor_label text NOT NULL,

    action        text NOT NULL,
    resource_type text NOT NULL,
    resource_id   text,
    project_id    uuid REFERENCES projects (id) ON DELETE SET NULL,

    -- Before and after as JSON rather than prose. §15.6 asks for the previous
    -- and new value, and a rendered sentence answers "what happened" but not
    -- "what exactly changed" -- which is the question an investigation asks.
    -- Values pass through the same redaction the rest of the system uses: an
    -- audit record must never be where a secret is finally written down
    -- (§15.3).
    before_value jsonb,
    after_value  jsonb,

    CONSTRAINT audit_logs_actor_kind_not_blank CHECK (length(btrim(actor_kind)) > 0),
    CONSTRAINT audit_logs_action_not_blank CHECK (length(btrim(action)) > 0),
    CONSTRAINT audit_logs_resource_type_not_blank CHECK (length(btrim(resource_type)) > 0)
);

CREATE INDEX audit_logs_occurred_idx ON audit_logs (occurred_at DESC);
CREATE INDEX audit_logs_project_idx ON audit_logs (project_id, occurred_at DESC);
CREATE INDEX audit_logs_resource_idx ON audit_logs (resource_type, resource_id);

-- Append-only, enforced by the database rather than by convention.
--
-- "We only ever insert" is a statement about the code written so far, not
-- about the code somebody writes next, and §15.13 forbids security through
-- obscurity. The trigger is the portable half of this control; a deployment
-- should ALSO revoke UPDATE and DELETE from the application role, which a
-- migration cannot do without knowing that role's name.
CREATE OR REPLACE FUNCTION audit_logs_are_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_are_append_only();

CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_are_append_only();
