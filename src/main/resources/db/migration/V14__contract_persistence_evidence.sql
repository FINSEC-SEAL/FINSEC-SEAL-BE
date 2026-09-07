-- Legacy contract rows remain readable by existing consumers. They cannot be approved
-- through the new persistence API without server-created integrity metadata.
CREATE TABLE contract_version_evidence (
    version_id uuid PRIMARY KEY REFERENCES safety_contract_versions(id) ON DELETE RESTRICT,
    base_policy_hash sha256_digest,
    resource_hash sha256_digest NOT NULL,
    review_json jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE FUNCTION finsec_guard_contract_version_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM safety_contract_versions WHERE id = OLD.version_id AND state IN ('APPROVED','REJECTED','SUPERSEDED')) THEN
        RAISE EXCEPTION 'terminal contract evidence is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER contract_version_evidence_guard BEFORE UPDATE OR DELETE ON contract_version_evidence
FOR EACH ROW EXECUTE FUNCTION finsec_guard_contract_version_evidence();
