# Login as Global Superadmin to set up the test data
POST http://localhost:3000/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

# Create a new organization "SecurityTestOrg"
POST http://localhost:3000/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "SecurityTestOrg_{{TEST_TIMESTAMP}}",
    "namespace": "security_test_org_{{TEST_TIMESTAMP}}",
    "description": "Organization for security verification"
}
HTTP 201
[Captures]
org_id: jsonpath "$.organization_id"

# Create a tenant superadmin "tenantadmin"
POST http://localhost:3000/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_id}},
    "email": "tenantadmin_{{TEST_TIMESTAMP}}@example.com",
    "username": "tenantadmin_{{TEST_TIMESTAMP}}",
    "password": "Password123",
    "first_login": false
}
HTTP 201
[Captures]
admin_user_id: jsonpath "$.user_id"

# Get "superadmin" group ID
GET http://localhost:3000/api/admin/groups?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
superadmin_group_id: jsonpath "$[?(@.name=='superadmin')].group_id" nth 0

# Assign "tenantadmin" to "superadmin"
POST http://localhost:3000/api/admin/users/{{admin_user_id}}/groups/{{superadmin_group_id}}?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200

# Create a regular user "regularuser"
POST http://localhost:3000/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_id}},
    "email": "regularuser_{{TEST_TIMESTAMP}}@example.com",
    "username": "regularuser_{{TEST_TIMESTAMP}}",
    "password": "Password123",
    "first_login": false
}
HTTP 201
[Captures]
regular_user_id: jsonpath "$.user_id"

# Login as Tenant Superadmin
POST http://localhost:3000/api/login
{
    "identity": "tenantadmin_{{TEST_TIMESTAMP}}@example.com",
    "password": "Password123",
    "namespace": "security_test_org_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Captures]
tenant_admin_token: jsonpath "$.token"

# TEST 1: Tenant Admin tries to CREATE organization - Should be Forbidden
POST http://localhost:3000/api/admin/organizations
Authorization: Bearer {{tenant_admin_token}}
{
    "name": "IllegalCreation_{{TEST_TIMESTAMP}}",
    "namespace": "illegal_creation_{{TEST_TIMESTAMP}}",
    "description": "Should fail"
}
HTTP 403
[Asserts]
body contains "Global Superadmin access required"

# TEST 2: Tenant Admin tries to DELETE organization - Should be Forbidden
DELETE http://localhost:3000/api/admin/organizations/{{org_id}}
Authorization: Bearer {{tenant_admin_token}}
HTTP 403
[Asserts]
body contains "Global Superadmin access required"

# Login as Regular User
POST http://localhost:3000/api/login
{
    "identity": "regularuser_{{TEST_TIMESTAMP}}@example.com",
    "password": "Password123",
    "namespace": "security_test_org_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Captures]
regular_user_token: jsonpath "$.token"

# TEST 3: Regular User tries to access Admin Dashboard - Should be Forbidden
GET http://localhost:3000/admin
Authorization: Bearer {{regular_user_token}}
HTTP 403

# TEST 4: Regular User tries to list users (Admin API) - Should be Forbidden
GET http://localhost:3000/api/admin/users?org_id={{org_id}}
Authorization: Bearer {{regular_user_token}}
HTTP 403
[Asserts]
body contains "Superadmin access required"
