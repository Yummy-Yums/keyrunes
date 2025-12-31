# Setup: Login as Superadmin
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

# 1. Create Organization A
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "Org A v10",
    "description": "First Org"
}
HTTP 201
[Captures]
org_a_id: jsonpath "$.organization_id"

# 2. Create Organization B
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "Org B v10",
    "description": "Second Org"
}
HTTP 201
[Captures]
org_b_id: jsonpath "$.organization_id"

# 2.5 Create 'users' group for Org A and Org B (Required for user creation)
POST {{BASE_URL}}/api/admin/groups
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_a_id}},
    "name": "users",
    "description": "Default users group"
}
HTTP 201

POST {{BASE_URL}}/api/admin/groups
Authorization: Bearer {{admin_token}}
{
    "organization_id": {{org_b_id}},
    "name": "users",
    "description": "Default users group"
}
HTTP 201

# 3. Create User in Org A via Admin API
POST {{BASE_URL}}/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "username": "user_org_a_v10",
    "email": "user_a_v10@org.com",
    "password": "Admin123",
    "organization_id": {{org_a_id}},
    "first_login": false
}
HTTP 201
[Asserts]
jsonpath "$.organization_id" == {{org_a_id}}

# 4. Create User in Org B via Admin API
POST {{BASE_URL}}/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "username": "user_org_b_v10",
    "email": "user_b_v10@org.com",
    "password": "Admin123",
    "organization_id": {{org_b_id}},
    "first_login": false
}
HTTP 201
[Asserts]
jsonpath "$.organization_id" == {{org_b_id}}
