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

# Create a new organization "UIHiddenOrg"
POST http://localhost:3000/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "UIHiddenOrg_{{TEST_TIMESTAMP}}",
    "namespace": "ui_hidden_org_{{TEST_TIMESTAMP}}",
    "description": "Organization to test UI hidden button"
}
HTTP 201
[Captures]
org_id: jsonpath "$.organization_id"

# Create a user "uihiddenuser" in "UIHiddenOrg"
POST http://localhost:3000/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_id}},
    "email": "uihidden_{{TEST_TIMESTAMP}}@example.com",
    "username": "uihiddenuser_{{TEST_TIMESTAMP}}",
    "password": "Password123",
    "first_login": false
}
HTTP 201
[Captures]
user_id: jsonpath "$.user_id"

# Get the "superadmin" group ID for UIHiddenOrg
GET http://localhost:3000/api/admin/groups?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
group_id: jsonpath "$[?(@.name=='admin')].group_id" nth 0

# Assign "uihiddenuser" to "superadmin" group
POST http://localhost:3000/api/admin/users/{{user_id}}/groups/{{group_id}}?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200

# Login as "uihiddenuser" (Tenant Superadmin)
POST http://localhost:3000/api/login
{
    "identity": "uihidden_{{TEST_TIMESTAMP}}@example.com",
    "password": "Password123",
    "namespace": "ui_hidden_org_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Captures]
tenant_token: jsonpath "$.token"

# Test: Get Admin Page as Tenant Superadmin
GET http://localhost:3000/admin
Authorization: Bearer {{tenant_token}}
HTTP 200
[Asserts]
body not contains ">Create Organization</button>"
