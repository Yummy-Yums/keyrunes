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

# Create a new organization "VisBugOrg"
POST http://localhost:3000/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "VisBugOrg_{{TEST_TIMESTAMP}}",
    "namespace": "visbug_org_{{TEST_TIMESTAMP}}",
    "description": "Organization to test visibility bug"
}
HTTP 201
[Captures]
org_id: jsonpath "$.organization_id"

# Create a user "visbuguser" in "VisBugOrg"
POST http://localhost:3000/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_id}},
    "email": "visbug_{{TEST_TIMESTAMP}}@example.com",
    "username": "visbuguser_{{TEST_TIMESTAMP}}",
    "password": "Password123",
    "first_login": false
}
HTTP 201
[Captures]
user_id: jsonpath "$.user_id"

# Get the "superadmin" group ID for VisBugOrg
# We need to find the group ID for "superadmin" in the new org.
GET http://localhost:3000/api/admin/groups?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
group_id: jsonpath "$[?(@.name=='superadmin')].group_id" nth 0

# Assign "visbuguser" to "superadmin" group of VisBugOrg
POST http://localhost:3000/api/admin/users/{{user_id}}/groups/{{group_id}}?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200

# Login as "visbuguser" (Tenant Superadmin)
POST http://localhost:3000/api/login
{
    "identity": "visbug_{{TEST_TIMESTAMP}}@example.com",
    "password": "Password123",
    "namespace": "visbug_org_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Captures]
tenant_token: jsonpath "$.token"

# Test: List organizations as Tenant Superadmin
# Should ONLY see their own organization (1 result), not all of them.
GET http://localhost:3000/api/admin/organizations
Authorization: Bearer {{tenant_token}}
HTTP 200
[Asserts]
jsonpath "$" count == 1
jsonpath "$[0].organization_id" == {{org_id}}
