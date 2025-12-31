# 1. Register User
POST {{BASE_URL}}/api/register
{
    "username": "test_user_hurl_v8",
    "email": "test_user_hurl_v8@example.com",
    "password": "Admin123"
}
HTTP 201
[Captures]
user_id: jsonpath "$.user.user_id"

# 2. Login
POST {{BASE_URL}}/api/login
{
    "identity": "test_user_hurl_v8@example.com",
    "password": "Admin123"
}
HTTP 200
[Captures]
token: jsonpath "$.token"

# 3. Check /api/me
GET {{BASE_URL}}/api/me
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.user_id" == {{user_id}}
jsonpath "$.username" == "test_user_hurl_v8"
