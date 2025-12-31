ALTER TABLE settings ADD COLUMN organization_id BIGINT REFERENCES organizations(organization_id);
