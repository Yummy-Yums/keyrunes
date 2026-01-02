-- Users table in tenant schema
CREATE TABLE IF NOT EXISTS users (
    user_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id BIGINT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_login BOOLEAN NOT NULL DEFAULT FALSE,
    reset_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_external_id_idx ON users (external_id);

-- Groups table in tenant schema
CREATE TABLE IF NOT EXISTS groups (
    group_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id BIGINT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS groups_external_id_idx ON groups (external_id);

-- Policies table in tenant schema
CREATE TABLE IF NOT EXISTS policies (
    policy_id BIGSERIAL PRIMARY KEY,
    external_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id BIGINT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    effect VARCHAR(10) NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    conditions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS policies_external_id_idx ON policies (external_id);

-- Join table: User <-> Groups
CREATE TABLE IF NOT EXISTS user_groups (
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by BIGINT REFERENCES users(user_id),
    PRIMARY KEY (user_id, group_id)
);

-- Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS password_reset_tokens_token_idx ON password_reset_tokens (token);

-- Settings
CREATE TABLE IF NOT EXISTS settings (
    settings_id SERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    key VARCHAR(100) NOT NULL UNIQUE,
    value TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


