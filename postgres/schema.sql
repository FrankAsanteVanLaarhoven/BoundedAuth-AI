-- Consumption records for bounded authority.
--
-- The primary key on jti is what makes a credential single-use. It is not an
-- optimisation and not a data-hygiene measure: it is the control. A second
-- attempt to spend the same credential raises a unique violation, and the
-- database resolves concurrent attempts internally, so correctness does not
-- depend on the application getting a check-then-act sequence right.
CREATE TABLE IF NOT EXISTS boundedauth_consumptions (
    jti         TEXT PRIMARY KEY,
    issuer      TEXT        NOT NULL,
    subject     TEXT        NOT NULL,
    method      TEXT        NOT NULL,
    -- The transaction this authority was spent on, so a spent credential can
    -- be tied back to what it authorised without retaining the credential.
    binding     TEXT        NOT NULL,
    reference   TEXT        NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS boundedauth_consumptions_reference_idx
    ON boundedauth_consumptions (reference);
CREATE INDEX IF NOT EXISTS boundedauth_consumptions_subject_idx
    ON boundedauth_consumptions (subject, consumed_at DESC);

-- A consumption record is evidence that a human authorised a specific movement
-- of money. Editing one rewrites that account; deleting one makes a spent
-- credential spendable again. Both are refused here rather than in application
-- code, which the next caller can bypass.
CREATE OR REPLACE FUNCTION boundedauth_consumptions_are_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'boundedauth_consumptions is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS boundedauth_consumptions_no_change ON boundedauth_consumptions;
CREATE TRIGGER boundedauth_consumptions_no_change
    BEFORE UPDATE OR DELETE ON boundedauth_consumptions
    FOR EACH ROW EXECUTE FUNCTION boundedauth_consumptions_are_immutable();
