# Setup - Create Admin
POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{admin_email}}",
  "password": "{{admin_password}}"
}
HTTP 200
[Captures]
token: jsonpath "$['token']"

# Test - Create user without group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}"
}
HTTP 201
[Captures]
new_user_id: jsonpath "$.user_id"
[Asserts]
# should belong to user group by default
jsonpath "$.groups" count == 1
jsonpath "$.groups[0]" == "users"

# Test - Create user with invalid group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}",
  "groups": ["invalid"]
}
HTTP 400
`invalid group specified: \`invalid\``

# Test - Create user with valid group
POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "email": "{{newUuid}}@example.com",
  "username": "{{group_user_username}}{{newDate}}",
  "password": "{{group_user_password}}",
  "groups": ["superadmin"]
}
HTTP 201
[Asserts]
# should have `superadmin` group
jsonpath "$.groups" count == 1
jsonpath "$.groups[0]" == "superadmin"

# Test - List all users
GET http://localhost:3000/api/admin/users
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$" isCollection
jsonpath "$[*].user_id" exists
jsonpath "$[*].username" exists
jsonpath "$[*].email" exists
jsonpath "$[*].groups" exists

# Test - List all groups
GET http://localhost:3000/api/admin/groups
Authorization: Bearer {{token}}
HTTP 200
[Captures]
superadmin_group_id: jsonpath "$[?(@.name=='superadmin')].group_id" nth 0
users_group_id: jsonpath "$[?(@.name=='users')].group_id" nth 0
[Asserts]
jsonpath "$" isCollection
jsonpath "$[?(@.name=='superadmin')]" exists
jsonpath "$[?(@.name=='users')]" exists

# Test - Create new group
POST http://localhost:3000/api/admin/groups
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "name": "developers_{{newDate}}",
  "description": "Development team"
}
HTTP 201
[Captures]
new_group_id: jsonpath "$.group_id"
new_group_name: jsonpath "$.name"
[Asserts]
jsonpath "$.name" startsWith "developers_"
jsonpath "$.description" == "Development team"
jsonpath "$.group_id" exists

# Test - Create duplicate group (should fail)
POST http://localhost:3000/api/admin/groups
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "name": "{{new_group_name}}",
  "description": "Duplicate"
}
HTTP 400

# Test - Assign user to group
POST http://localhost:3000/api/admin/users/{{new_user_id}}/groups/{{new_group_id}}
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.message" == "User assigned to group successfully"

# Test - Remove user from group
DELETE http://localhost:3000/api/admin/users/{{new_user_id}}/groups/{{new_group_id}}
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.message" == "User removed from group successfully"

# Test - Get admin dashboard
GET http://localhost:3000/api/admin/dashboard
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.total_users" isInteger
jsonpath "$.total_groups" isInteger
jsonpath "$.total_policies" isInteger
jsonpath "$.current_admin.username" exists
jsonpath "$.current_admin.groups" includes "superadmin"

# Test - List all policies
GET http://localhost:3000/api/admin/policies
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$" isCollection
jsonpath "$[*].policy_id" exists
jsonpath "$[*].name" exists

# Test - Check permission (user with superadmin should have full access)
POST http://localhost:3000/api/admin/check-permission
Content-Type: application/json
Authorization: Bearer {{token}}
{
  "user_id": {{new_user_id}},
  "group_name": "users",
  "resource": "user:*",
  "action": "read"
}
HTTP 200
[Asserts]
jsonpath "$.user_id" == {{new_user_id}}
jsonpath "$.has_permission" isBoolean

# Test - Access without authentication (should fail)
GET http://localhost:3000/api/admin/users
HTTP 401

# Test - Access with non-superadmin (create regular user first)
POST http://localhost:3000/api/register
Content-Type: application/json
{
  "email": "regular_{{newUuid}}@example.com",
  "username": "regular_{{newDate}}",
  "password": "Regular123"
}
HTTP 201
[Captures]
regular_token: jsonpath "$.token"

# Try to access admin endpoint with regular user
GET http://localhost:3000/api/admin/users
Authorization: Bearer {{regular_token}}
HTTP 403
