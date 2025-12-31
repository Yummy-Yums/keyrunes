# 1. Login as Superadmin (Assuming user 1 is superadmin created by default/migration or setup)
POST {{BASE_URL}}/api/login
{
    "identity": "admin@example.com",
    "password": "Admin123"
}
HTTP 200
[Captures]
token: jsonpath "$.token"

# 2. List Organizations to get ID and Key
GET {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{token}}
HTTP 200
[Captures]
org_id: jsonpath "$[0].organization_id"
old_key: jsonpath "$[0].secret_key"

# 3. Rotate Key
POST {{BASE_URL}}/api/admin/organizations/{{org_id}}/rotate-key
Authorization: Bearer {{token}}
HTTP 200
[Captures]
new_key: jsonpath "$.secret_key"
[Asserts]
jsonpath "$.secret_key" != "{{old_key}}"

# 4. Verify New Key Persisted
GET {{BASE_URL}}/api/admin/organizations
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$[0].secret_key" == "{{new_key}}"
