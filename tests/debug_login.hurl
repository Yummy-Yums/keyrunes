# 1. Register user (might fail if exists, that's fine, we continue to login)
POST http://localhost:3000/api/register
{
    "email": "jonatas_test@example.com",
    "username": "jonatas_test",
    "password": "asdasdasd",
    "namespace": "public"
}
# We don't assert 201 because it might already exist (400)

# 2. Login via Form (should set cookie and redirect)
POST http://localhost:3000/login
[FormParams]
identity: jonatas_test
password: asdasdasd
namespace: public
HTTP 303
[Asserts]
header "Location" == "/dashboard"
cookie "jwt_token" exists

# 3. Access /api/me (uses cookie from step 2)
GET http://localhost:3000/api/me
HTTP 200
[Asserts]
jsonpath "$.username" == "jonatas_test"
