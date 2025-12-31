-- Create organizations table
CREATE TABLE IF NOT EXISTS organizations (
    organization_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS organizations_external_id_idx ON organizations (external_id);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_name_idx ON organizations (name);

-- Trigger for organization updated_at
CREATE TRIGGER trg_set_updated_at_organizations
BEFORE UPDATE ON organizations
FOR EACH ROW
EXECUTE PROCEDURE set_updated_at();

-- Insert default organization
INSERT INTO organizations (name, description)
VALUES ('Default Organization', 'Default organization for existing data')
ON CONFLICT (name) DO NOTHING;

-- Add organization_id to users, groups, policies
-- We assume "Default Organization" has ID 1 because it's the first insert, but let's be safe and look it up
DO $$
DECLARE
    default_org_id BIGINT;
BEGIN
    SELECT organization_id INTO default_org_id FROM organizations WHERE name = 'Default Organization';

    -- Users
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='organization_id') THEN
        EXECUTE format('ALTER TABLE users ADD COLUMN organization_id BIGINT DEFAULT %s REFERENCES organizations(organization_id) ON DELETE CASCADE', default_org_id);
        ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL;
    END IF;

    -- Groups
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='groups' AND column_name='organization_id') THEN
        EXECUTE format('ALTER TABLE groups ADD COLUMN organization_id BIGINT DEFAULT %s REFERENCES organizations(organization_id) ON DELETE CASCADE', default_org_id);
        ALTER TABLE groups ALTER COLUMN organization_id SET NOT NULL;
    END IF;

    -- Policies
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policies' AND column_name='organization_id') THEN
        EXECUTE format('ALTER TABLE policies ADD COLUMN organization_id BIGINT DEFAULT %s REFERENCES organizations(organization_id) ON DELETE CASCADE', default_org_id);
        ALTER TABLE policies ALTER COLUMN organization_id SET NOT NULL;
    END IF;
END $$;

-- Update indexes for multi-tenancy scoping

-- Groups: name was unique globally. Now unique per organization.
-- We need to drop that constraint and create a unique index on (organization_id, name).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'groups_name_key') THEN
        ALTER TABLE groups DROP CONSTRAINT groups_name_key;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS groups_org_name_idx ON groups (organization_id, name);

-- Policies: similar to groups
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policies_name_key') THEN
        ALTER TABLE policies DROP CONSTRAINT policies_name_key;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS policies_org_name_idx ON policies (organization_id, name);

-- Users: keeping username/email global as per plan, so no index changes for users needed right now.
