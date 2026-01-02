# 1. Register a new user (This will be our Org Admin/User)
POST http://localhost:3000/api/register
{
    "email": "hurl_user_v7@example.com",
    "username": "hurl_user_v7",
    "password": "Password123!",
    "namespace": "public"
}
HTTP 201
[Captures]
token: jsonpath "$.token"

# 2. Login as the new user
POST http://localhost:3000/api/login
{
    "identity": "hurl_user_v7",
    "password": "Password123!",
    "namespace": "public"
}
HTTP 200
[Captures]
token_login: jsonpath "$.token"

# 3. Access Dashboard
GET http://localhost:3000/dashboard
Cookie: jwt_token={{token}}
HTTP 200
[Asserts]
body contains "Dashboard"

# 4. Access Profile Page
GET http://localhost:3000/profile
Cookie: jwt_token={{token}}
HTTP 200
[Asserts]
body contains "Edit Profile"
body contains "hurl_user_v7@example.com"

# 5. Update Profile
POST http://localhost:3000/profile
Cookie: jwt_token={{token}}
[FormParams]
username: hurl_user_v7_updated
email: hurl_updated_v7@example.com
HTTP 200
[Asserts]
body contains "Profile updated successfully"
body contains "hurl_user_v7_updated"

# 6. Verify Profile Update via API
GET http://localhost:3000/api/me
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.username" == "hurl_user_v7_updated"
jsonpath "$.email" == "hurl_updated_v7@example.com"

# 7. Check Organization Secret (Protected, expect 403 for regular user)
POST http://localhost:3000/api/org/secret/rotate
Authorization: Bearer {{token}}
HTTP 403
[Asserts]
body contains "Insufficient permissions"

# 8. Reset Password Flow (Request)
POST http://localhost:3000/api/forgot-password
{
    "email": "hurl_updated_v7@example.com",
    "namespace": "public"
}
HTTP 200
[Captures]
reset_token: jsonpath "$.reset_url" regex "forgot_password=([a-zA-Z0-9-]+)"

# 9. Reset Password Flow (Submit)
POST http://localhost:3000/api/reset-password
{
    "token": "{{reset_token}}",
    "new_password": "NewPassword123!",
    "namespace": "public"
}
HTTP 200

# 10. Login with New Password
POST http://localhost:3000/api/login
{
    "identity": "hurl_user_v7_updated",
    "password": "NewPassword123!",
    "namespace": "public"
}
HTTP 200
