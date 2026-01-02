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

# 1. Create a User (to assign later)
POST {{BASE_URL}}/api/register
{
    "username": "group_member_{{TEST_TIMESTAMP}}",
    "email": "member_{{TEST_TIMESTAMP}}@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 201
[Captures]
user_id: jsonpath "$.user.user_id"

# 2. Create a Group
POST {{BASE_URL}}/api/admin/groups
Authorization: Bearer {{admin_token}}
{
    "organization_id": 1,
    "name": "Developers_{{TEST_TIMESTAMP}}",
    "description": "Dev Team"
}
HTTP 201
[Captures]
group_id: jsonpath "$.group_id"

# 3. Assign User to Group
POST {{BASE_URL}}/api/admin/users/{{user_id}}/groups/{{group_id}}
Authorization: Bearer {{admin_token}}
HTTP 200

# 4. Verify via /api/me (Check first to isolate DB vs Query)
POST {{BASE_URL}}/api/login
{
    "identity": "member_{{TEST_TIMESTAMP}}@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
member_token: jsonpath "$.token"

GET {{BASE_URL}}/api/me
Authorization: Bearer {{member_token}}
HTTP 200
[Asserts]
jsonpath "$.groups" contains "Developers_{{TEST_TIMESTAMP}}"