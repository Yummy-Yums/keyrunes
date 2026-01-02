#!/bin/bash

set -e

PSQL_CMD="psql postgres://postgres_user:pass123@localhost:5432/keyrunes"

echo "Cleaning test data..."

$PSQL_CMD -c "TRUNCATE TABLE password_reset_tokens, user_groups, users, groups CASCADE;" 2>&1 | grep -v "^$" || true
$PSQL_CMD -c "DELETE FROM organizations WHERE organization_id > 1;" 2>&1 | grep -v "^$" || true

echo "Test data cleaned!"
echo ""
echo "Creating default superadmin..."

cargo run --bin cli -- create-superadmin \
  --email admin@exemple.com \
  --username admin \
  --password Admin123 2>&1 | tail -3

echo ""
echo "Ready for Hurl tests!"
