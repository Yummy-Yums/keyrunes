# 1. Login as Superadmin
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123"
}
HTTP 200
[Captures]
token: jsonpath "$.token"
user_id: jsonpath "$.user.user_id"

# 2. Check Permission WITHOUT X-Organization-Key (Should succeed for Superadmin)
POST {{BASE_URL}}/api/check-permission
Authorization: Bearer {{token}}
{
    "user_id": {{user_id}},
    "resource": "any_resource",
    "action": "any_action"
}
HTTP 200
[Asserts]
jsonpath "$.allowed" exists
