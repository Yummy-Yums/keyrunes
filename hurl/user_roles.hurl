POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{admin_email}}",
  "password": "{{admin_password}}"
}
HTTP 200
[Captures]
admin_token: jsonpath "$.token"

POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{admin_token}}
{
  "email": "multiRole_{{newUuid}}@example.com",
  "username": "multirole_{{newDate}}",
  "password": "{{test_user_password}}",
  "groups": ["superadmin"]
}
HTTP 201
[Captures]
test_user_id: jsonpath "$.user_id"
test_user_email: jsonpath "$.email"
[Asserts]
jsonpath "$.groups" count == 1
jsonpath "$.groups[0]" == "superadmin"

GET http://localhost:3000/api/admin/groups
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
users_group_id: jsonpath "$[?(@.name=='users')].group_id" nth 0
[Asserts]
jsonpath "$[?(@.name=='users')]" exists

POST http://localhost:3000/api/admin/users/{{test_user_id}}/groups/{{users_group_id}}
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$.message" == "User assigned to group successfully"

GET http://localhost:3000/api/admin/users
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$[?(@.user_id=={{test_user_id}})].groups" count == 1
jsonpath "$[?(@.user_id=={{test_user_id}})].groups[0]" count == 2

POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{test_user_email}}",
  "password": "{{test_user_password}}"
}
HTTP 200
[Captures]
test_user_token: jsonpath "$.token"
[Asserts]
jsonpath "$.token" exists
jsonpath "$.user.groups" count == 2
jsonpath "$.user.groups" contains "superadmin"
jsonpath "$.user.groups" contains "users"

GET http://localhost:3000/api/admin/dashboard
Authorization: Bearer {{test_user_token}}
HTTP 200
[Asserts]
jsonpath "$.total_users" isInteger
jsonpath "$.total_groups" isInteger
jsonpath "$.current_admin.username" exists
jsonpath "$.current_admin.groups" count == 2
jsonpath "$.current_admin.groups" contains "superadmin"
jsonpath "$.current_admin.groups" contains "users"

GET http://localhost:3000/api/admin/users
Authorization: Bearer {{test_user_token}}
HTTP 200
[Asserts]
jsonpath "$" isCollection
jsonpath "$[*].user_id" exists

POST http://localhost:3000/api/admin/user
Content-Type: application/json
Authorization: Bearer {{test_user_token}}
{
  "email": "created_by_multirole_{{newUuid}}@example.com",
  "username": "created_{{newDate}}",
  "password": "Created123"
}
HTTP 201
[Captures]
created_user_id: jsonpath "$.user_id"
[Asserts]
jsonpath "$.user_id" exists
jsonpath "$.groups" contains "users"

POST http://localhost:3000/api/admin/check-permission
Content-Type: application/json
Authorization: Bearer {{test_user_token}}
{
  "user_id": {{test_user_id}},
  "group_name": "users",
  "resource": "user:self",
  "action": "read"
}
HTTP 200
[Asserts]
jsonpath "$.user_id" == {{test_user_id}}
jsonpath "$.group_name" == "users"
jsonpath "$.has_permission" isBoolean

POST http://localhost:3000/api/admin/check-permission
Content-Type: application/json
Authorization: Bearer {{test_user_token}}
{
  "user_id": {{test_user_id}},
  "group_name": "superadmin",
  "resource": "admin:*",
  "action": "*"
}
HTTP 200
[Asserts]
jsonpath "$.user_id" == {{test_user_id}}
jsonpath "$.group_name" == "superadmin"
jsonpath "$.has_permission" isBoolean

GET http://localhost:3000/api/admin/groups
Authorization: Bearer {{admin_token}}
HTTP 200
[Captures]
superadmin_group_id: jsonpath "$[?(@.name=='superadmin')].group_id" nth 0

DELETE http://localhost:3000/api/admin/users/{{test_user_id}}/groups/{{superadmin_group_id}}
Authorization: Bearer {{admin_token}}
HTTP 200
[Asserts]
jsonpath "$.message" == "User removed from group successfully"

POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{test_user_email}}",
  "password": "{{test_user_password}}"
}
HTTP 200
[Captures]
users_only_token: jsonpath "$.token"
[Asserts]
jsonpath "$.user.groups" count == 1
jsonpath "$.user.groups[0]" == "users"

GET http://localhost:3000/api/admin/users
Authorization: Bearer {{users_only_token}}
HTTP 403
