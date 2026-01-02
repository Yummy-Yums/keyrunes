-- Migration to synchronize all existing tenant schemas
DO $$
DECLARE
    schema_rec RECORD;
    org_id_val BIGINT;
BEGIN
    FOR schema_rec IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'public') AND schema_name NOT LIKE 'pg_toast%' LOOP
        -- Check if this schema looks like a tenant (has a users table)
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = schema_rec.schema_name AND table_name = 'users') THEN
            RAISE NOTICE 'Syncing schema: %', schema_rec.schema_name;
            
            -- 1. Sync groups table
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = schema_rec.schema_name AND table_name = 'groups') THEN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'groups' AND column_name = 'external_id') THEN
                    EXECUTE format('ALTER TABLE %I.groups ADD COLUMN external_id UUID NOT NULL DEFAULT gen_random_uuid()', schema_rec.schema_name);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'groups' AND column_name = 'organization_id') THEN
                    EXECUTE format('ALTER TABLE %I.groups ADD COLUMN organization_id BIGINT', schema_rec.schema_name);
                END IF;
            END IF;

            -- 2. Sync users table
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'users' AND column_name = 'external_id') THEN
                EXECUTE format('ALTER TABLE %I.users ADD COLUMN external_id UUID NOT NULL DEFAULT gen_random_uuid()', schema_rec.schema_name);
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'users' AND column_name = 'reset_password') THEN
                EXECUTE format('ALTER TABLE %I.users ADD COLUMN reset_password BOOLEAN NOT NULL DEFAULT FALSE', schema_rec.schema_name);
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'users' AND column_name = 'organization_id') THEN
                EXECUTE format('ALTER TABLE %I.users ADD COLUMN organization_id BIGINT', schema_rec.schema_name);
            END IF;

            -- 3. Sync policies table
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = schema_rec.schema_name AND table_name = 'policies') THEN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'policies' AND column_name = 'external_id') THEN
                    EXECUTE format('ALTER TABLE %I.policies ADD COLUMN external_id UUID NOT NULL DEFAULT gen_random_uuid()', schema_rec.schema_name);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'policies' AND column_name = 'organization_id') THEN
                    EXECUTE format('ALTER TABLE %I.policies ADD COLUMN organization_id BIGINT', schema_rec.schema_name);
                END IF;
            END IF;

            -- 4. Sync user_groups table
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = schema_rec.schema_name AND table_name = 'user_groups') THEN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'user_groups' AND column_name = 'assigned_by') THEN
                    EXECUTE format('ALTER TABLE %I.user_groups ADD COLUMN assigned_by BIGINT', schema_rec.schema_name);
                END IF;
            END IF;

            -- 5. Sync settings table
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = schema_rec.schema_name AND table_name = 'settings') THEN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = schema_rec.schema_name AND table_name = 'settings' AND column_name = 'organization_id') THEN
                    EXECUTE format('ALTER TABLE %I.settings ADD COLUMN organization_id BIGINT', schema_rec.schema_name);
                END IF;
            END IF;

            -- 6. Attempt to populate organization_id and default groups if found in organizations table
            EXECUTE format('SELECT organization_id FROM public.organizations WHERE namespace = %L', schema_rec.schema_name) INTO org_id_val;
            
            IF org_id_val IS NOT NULL THEN
                EXECUTE format('UPDATE %I.users SET organization_id = %L WHERE organization_id IS NULL', schema_rec.schema_name, org_id_val);
                EXECUTE format('UPDATE %I.groups SET organization_id = %L WHERE organization_id IS NULL', schema_rec.schema_name, org_id_val);
                EXECUTE format('UPDATE %I.policies SET organization_id = %L WHERE organization_id IS NULL', schema_rec.schema_name, org_id_val);
                EXECUTE format('UPDATE %I.settings SET organization_id = %L WHERE organization_id IS NULL', schema_rec.schema_name, org_id_val);

                -- Ensure default groups exist
                EXECUTE format('INSERT INTO %I.groups (external_id, organization_id, name, description) VALUES (gen_random_uuid(), %L, %L, %L) ON CONFLICT (name) DO NOTHING', 
                    schema_rec.schema_name, org_id_val, 'superadmin', 'Super administrators');
                EXECUTE format('INSERT INTO %I.groups (external_id, organization_id, name, description) VALUES (gen_random_uuid(), %L, %L, %L) ON CONFLICT (name) DO NOTHING', 
                    schema_rec.schema_name, org_id_val, 'users', 'Regular users');
            END IF;
        END IF;
    END LOOP;
END $$;
