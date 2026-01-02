-- Clean all data
TRUNCATE TABLE password_reset_tokens, user_groups, user_policies, group_policies, users, groups, policies, organizations, settings CASCADE;

-- Reset sequences
ALTER SEQUENCE users_user_id_seq RESTART WITH 1;
ALTER SEQUENCE groups_group_id_seq RESTART WITH 3;
ALTER SEQUENCE policies_policy_id_seq RESTART WITH 4;
ALTER SEQUENCE organizations_organization_id_seq RESTART WITH 2;
ALTER SEQUENCE settings_settings_id_seq RESTART WITH 2;

-- Seed mandatory data for public namespace
INSERT INTO organizations (organization_id, name, external_id, secret_key, namespace) 
VALUES (1, 'Default Organization', gen_random_uuid(), gen_random_uuid(), 'public');

INSERT INTO groups (group_id, organization_id, name, description) VALUES 
(1, 1, 'superadmin', 'Super administrators'),
(2, 1, 'users', 'Regular users');

INSERT INTO policies (policy_id, name, description, resource, action, effect) VALUES 
(1, 'full_access', 'Full access to all resources', '*', '*', 'ALLOW'),
(2, 'read_only', 'Read-only access to user resources', 'user:*', 'read', 'ALLOW'),
(3, 'user_self_manage', 'Users can manage their own data', 'user:self', '*', 'ALLOW');

INSERT INTO group_policies (group_id, policy_id) VALUES (1, 1), (2, 2), (2, 3);

INSERT INTO settings (key, value, description) VALUES ('BASE_URL', 'http://localhost:3000', 'Base URL for the application');
