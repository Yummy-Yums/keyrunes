# User Deletion Test Suite

# 1. Global Superadmin creates a user to delete
POST http://localhost:3000/api/register
Content-Type: application/json
{
    "email": "todelete_global_v2@example.com",
    "username": "todelete_global_v2",
    "password": "password123",
    "organization_id": 1,
    "namespace": "public"
}
HTTP 201
[Captures]
global_user_id: jsonpath "$.user.user_id"
global_user_token: jsonpath "$.token"

# 2. Authenticate as Global Superadmin (from previous tests or default)
POST http://localhost:3000/api/login
Content-Type: application/json
{
    "identity": "admin",
    "password": "Admin123",
    "namespace": "public"
}
HTTP 200
[Captures]
superadmin_token: jsonpath "$.token"
superadmin_id: jsonpath "$.user.user_id"

# 3. Global Superadmin deletes the user
DELETE http://localhost:3000/api/admin/users/{{global_user_id}}
Authorization: Bearer {{superadmin_token}}
HTTP 204

# 4. Verify user is gone (login should fail)
POST http://localhost:3000/api/login
Content-Type: application/json
{
    "identity": "todelete_global_v2",
    "password": "password123",
    "namespace": "public"
}
HTTP 401


# 5. Tenant Isolation Test

# 6. Global Superadmin tries to delete themselves (Should fail)
DELETE http://localhost:3000/api/admin/users/{{superadmin_id}}
Authorization: Bearer {{superadmin_token}}
HTTP 400
[Asserts]
body contains "Cannot delete yourself"
