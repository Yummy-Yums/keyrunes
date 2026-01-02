# Setup: Login as Superadmin
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

# 1. Create Organization A
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "Org A {{TEST_TIMESTAMP}}",
    "description": "First Org",
    "namespace": "org_a_{{TEST_TIMESTAMP}}",
    "base_url": null
}
HTTP 201
[Captures]
org_a_id: jsonpath "$.organization_id"

# 2. Create Organization B
POST {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{admin_token}}
{
    "name": "Org B {{TEST_TIMESTAMP}}",
    "description": "Second Org",
    "namespace": "org_b_{{TEST_TIMESTAMP}}",
    "base_url": null
}
HTTP 201
[Captures]
org_b_id: jsonpath "$.organization_id"

# 3. Create User in Org A via Admin API
POST {{BASE_URL}}/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "username": "user_org_a_{{TEST_TIMESTAMP}}",
    "email": "user_a_{{TEST_TIMESTAMP}}@org.com",
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
    "username": "user_org_b_{{TEST_TIMESTAMP}}",
    "email": "user_b_{{TEST_TIMESTAMP}}@org.com",
    "password": "Admin123",
    "organization_id": {{org_b_id}},
    "first_login": false
}
HTTP 201
[Asserts]
jsonpath "$.organization_id" == {{org_b_id}}
