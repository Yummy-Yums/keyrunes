# 1. Login as Superadmin
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

# 2. Create a test user in public namespace
POST {{BASE_URL}}/api/admin/user
Authorization: Bearer {{admin_token}}
{
    "email": "testuser_{{TEST_TIMESTAMP}}@example.com",
    "username": "testuser_{{TEST_TIMESTAMP}}",
    "password": "Password123",
    "first_login": false,
    "organization_id": 1
}
HTTP 201
[Captures]
user_id: jsonpath "$.user_id"
user_email: jsonpath "$.email"

# 3. Admin Update User
PATCH {{BASE_URL}}/api/admin/users/{{user_id}}?org_id=1
Authorization: Bearer {{admin_token}}
{
    "first_login": true,
    "username": "updated_user_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Asserts]
jsonpath "$.first_login" == true
jsonpath "$.username" == "updated_user_{{TEST_TIMESTAMP}}"

# 4. Admin Reset Password (Direct)
POST {{BASE_URL}}/api/admin/users/{{user_id}}/reset-password?org_id=1
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
temp_password: jsonpath "$.temporary_password"

# 5. User Login with Temp Password
POST {{BASE_URL}}/api/login
{
    "identity": "{{user_email}}",
    "password": "{{temp_password}}",
    "namespace": "public"
}
HTTP 200
[Asserts]
jsonpath "$.requires_password_change" == true
[Captures]
user_token: jsonpath "$.token"

# 6. User Change Password
POST {{BASE_URL}}/api/user/change-password
Authorization: Bearer {{user_token}}
{
    "current_password": "{{temp_password}}",
    "new_password": "NewSecurePassword123!"
}
HTTP 200

# 7. User Login with New Password
POST {{BASE_URL}}/api/login
{
    "identity": "{{user_email}}",
    "password": "NewSecurePassword123!",
    "namespace": "public"
}
HTTP 200
[Asserts]
jsonpath "$.requires_password_change" == false
[Captures]
new_user_token: jsonpath "$.token"

# 8. User Update Own Profile
PATCH {{BASE_URL}}/api/user/profile
Authorization: Bearer {{new_user_token}}
{
    "username": "self_updated_{{TEST_TIMESTAMP}}"
}
HTTP 200
[Asserts]
jsonpath "$.username" == "self_updated_{{TEST_TIMESTAMP}}"

# 9. Admin Send Reset Email (Check 200 OK)
POST {{BASE_URL}}/api/admin/users/{{user_id}}/send-reset?org_id=1
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$.message" == "Reset email sent"
