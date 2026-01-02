# 1. Login as Superadmin
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
superadmin_token: jsonpath "$.token"

# 2. Create First Organization (to be deleted)
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{superadmin_token}}
{
    "name": "Temp Org {{TEST_TIMESTAMP}}",
    "description": "Will be deleted",
    "namespace": "temp_org_{{TEST_TIMESTAMP}}",
    "base_url": null
}
HTTP 201
[Captures]
temp_org_id: jsonpath "$.organization_id"

# 3. Delete the First Organization
DELETE {{BASE_URL}}/api/admin/organizations/{{temp_org_id}}
Authorization: Bearer {{superadmin_token}}
HTTP 204

# 4. Create Second Organization (permanent)
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{superadmin_token}}
{
    "name": "Company {{TEST_TIMESTAMP}}",
    "description": "Main organization",
    "namespace": "company_{{TEST_TIMESTAMP}}",
    "base_url": null
}
HTTP 201
[Captures]
org_id: jsonpath "$.organization_id"
org_namespace: jsonpath "$.namespace"

# 5. Create 'marketing' group for the organization
POST {{BASE_URL}}/api/admin/groups
Authorization: Bearer {{superadmin_token}}
{
    "organization_id": {{org_id}},
    "name": "marketing",
    "description": "Marketing department"
}
HTTP 201

# 6. Register Admin User for the organization (via public API)
POST {{BASE_URL}}/api/register
{
    "username": "org_admin_{{TEST_TIMESTAMP}}",
    "email": "admin_{{TEST_TIMESTAMP}}@company.com",
    "password": "Admin123",
    "organization_id": {{org_id}},
    "namespace": "{{org_namespace}}"
}
HTTP 201
[Asserts]
jsonpath "$.user.organization_id" == {{org_id}}
[Captures]
admin_user_id: jsonpath "$.user.user_id"
admin_token_from_register: jsonpath "$.token"

# 7. Login as the Admin User (verify login works)
POST {{BASE_URL}}/api/login
{
    "identity": "admin_{{TEST_TIMESTAMP}}@company.com",
    "password": "Admin123",
    "namespace": "{{org_namespace}}"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

# 8. Admin creates a new group
POST {{BASE_URL}}/api/admin/groups
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_id}},
    "name": "developers_{{TEST_TIMESTAMP}}",
    "description": "Development team"
}
HTTP 201
[Captures]
dev_group_id: jsonpath "$.group_id"

# 9. Admin creates a Regular User
POST {{BASE_URL}}/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "username": "regular_user_{{TEST_TIMESTAMP}}",
    "email": "user_{{TEST_TIMESTAMP}}@company.com",
    "password": "User1234",
    "organization_id": {{org_id}},
    "groups": ["users"],
    "first_login": false
}
HTTP 201
[Asserts]
jsonpath "$.organization_id" == {{org_id}}
jsonpath "$.groups" includes "users"
[Captures]
user_id: jsonpath "$.user_id"

# 10. Admin assigns user to developers group  
POST {{BASE_URL}}/api/admin/users/{{user_id}}/groups/{{dev_group_id}}?org_id={{org_id}}
Authorization: Bearer {{admin_token}}
HTTP 200

# 11. Regular User Login
POST {{BASE_URL}}/api/login
{
    "identity": "user_{{TEST_TIMESTAMP}}@company.com",
    "password": "User1234",
    "namespace": "{{org_namespace}}"
}
HTTP 200
[Captures]
user_token: jsonpath "$.token"
[Asserts]
jsonpath "$.user.username" == "regular_user_{{TEST_TIMESTAMP}}"
jsonpath "$.user.groups" includes "users"
jsonpath "$.user.groups" includes "developers_{{TEST_TIMESTAMP}}"

# 12. Verify Regular User can access /api/me
GET {{BASE_URL}}/api/me
Authorization: Bearer {{user_token}}
HTTP 200
[Asserts]
jsonpath "$.user_id" == {{user_id}}
jsonpath "$.username" == "regular_user_{{TEST_TIMESTAMP}}"
jsonpath "$.organization_id" == {{org_id}}
