DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'namespace') THEN
        ALTER TABLE organizations ADD COLUMN namespace VARCHAR(63);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'base_url') THEN
        ALTER TABLE organizations ADD COLUMN base_url VARCHAR(255);
    END IF;
END $$;

-- Update existing organizations to have unique namespaces
UPDATE organizations SET namespace = 'public' WHERE name = 'Default Organization' AND namespace IS NULL;

-- Others get a generated namespace based on ID to ensure uniqueness
UPDATE organizations SET namespace = 'org_' || organization_id WHERE namespace IS NULL;

-- Now apply constraints
DO $$
BEGIN
    ALTER TABLE organizations ALTER COLUMN namespace SET NOT NULL;
EXCEPTION
    WHEN others THEN NULL;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organizations_namespace_key') THEN
        ALTER TABLE organizations ADD CONSTRAINT organizations_namespace_key UNIQUE (namespace);
    END IF;
END $$;
