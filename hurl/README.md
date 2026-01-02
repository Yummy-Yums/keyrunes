# Running Hurl Tests

## Option 1: Using the Script (RECOMMENDED)

The `hurl/run_hurl_tests.sh` script automatically handles cleanup and configures all variables:

```bash
bash hurl/run_hurl_tests.sh
```

Or via Makefile (server must be running):
```bash
make test-hurl
```

## Option 2: Direct Execution

To run Hurl tests directly, you need to define the variables:

```bash
# Set timestamp for unique tests
export TEST_TIMESTAMP=$(date +%s)

# Run all tests
hurl --variable BASE_URL=http://localhost:3000 \
     --variable TEST_TIMESTAMP=$TEST_TIMESTAMP \
     --test hurl/*.hurl
```

Or in one line:
```bash
TEST_TIMESTAMP=$(date +%s) hurl --variable BASE_URL=http://localhost:3000 --variable TEST_TIMESTAMP=$TEST_TIMESTAMP --test hurl/*.hurl
```

### Tests that DON'T need TEST_TIMESTAMP:
- `superadmin_bypass.hurl`
- `org_key_mgmt.hurl`

Can be run like this:
```bash
hurl --variable BASE_URL=http://localhost:3000 --test hurl/superadmin_bypass.hurl hurl/org_key_mgmt.hurl
```

### Tests that NEED TEST_TIMESTAMP:
- `user_lifecycle.hurl`
- `group_management.hurl`  
- `org_isolation.hurl`

Must be run with:
```bash
export TEST_TIMESTAMP=$(date +%s)
hurl --variable BASE_URL=http://localhost:3000 --variable TEST_TIMESTAMP=$TEST_TIMESTAMP --test hurl/user_lifecycle.hurl hurl/group_management.hurl hurl/org_isolation.hurl
```

## Option 3: Manual Cleanup Before Tests

If you want to run without the script but with cleanup:

```bash
# Database cleanup
bash hurl/cleanup_test_data.sh

# Run tests
export TEST_TIMESTAMP=$(date +%s)
hurl --variable BASE_URL=http://localhost:3000 --variable TEST_TIMESTAMP=$TEST_TIMESTAMP --test hurl/*.hurl
```

## Required Variables

| Variable | Description | Required |
|----------|-----------|-------------|
| `BASE_URL` | Server URL (e.g., `http://localhost:3000`) | ✅ Yes |
| `TEST_TIMESTAMP` | Timestamp for unique data | ⚠️ Yes for 3 tests |

## Troubleshooting

**Error: "you must set the variable TEST_TIMESTAMP"**
- Solution: Define the variable before running: `export TEST_TIMESTAMP=$(date +%s)`

**Error: "organization already exists" or "email already registered"**
- Solution: Run `bash hurl/cleanup_test_data.sh` or use the main script

**Error 422 on login**
- Cause: Missing `namespace` field in JSON
- The `.hurl` files already have this fixed, make sure you're using the updated version
