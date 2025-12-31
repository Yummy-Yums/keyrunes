-- Add secret_key column to organizations table
ALTER TABLE organizations ADD COLUMN secret_key UUID NOT NULL DEFAULT gen_random_uuid();

-- Ensure secret_key is unique
ALTER TABLE organizations ADD CONSTRAINT organizations_secret_key_key UNIQUE (secret_key);
