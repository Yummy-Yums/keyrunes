POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{email}}",
  "password": "{{password}}"
}
HTTP 200
[Captures]
user_token: jsonpath "$.token"
user_id: jsonpath "$.user.user_id"
username: jsonpath "$.user.username"
user_email: jsonpath "$.user.email"
user_groups: jsonpath "$.user.groups"
[Asserts]
jsonpath "$.token" exists
jsonpath "$.user.user_id" exists
jsonpath "$.user.groups" isCollection
jsonpath "$.user.groups" count >= 1

POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{email}}",
  "password": "{{password}}"
}
HTTP 200
[Asserts]
POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{email}}",
  "password": "{{password}}"
}
HTTP 200
[Captures]
is_superadmin: jsonpath "$.user.groups" contains "superadmin"

GET http://localhost:3000/api/admin/dashboard
Authorization: Bearer {{user_token}}
HTTP *
[Asserts]
status >= 200
status < 500

POST http://localhost:3000/api/login
Content-Type: application/json
{
  "identity": "{{email}}",
  "password": "{{password}}"
}
HTTP 200
