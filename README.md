# JWT Token Translator
JWT Token Translator is a Traefik middleware that translates an incoming UUID access token, from either an HTTP
Authorization header or a GWTOKEN cookie, to an internal JWT passed along as an HTTP Authorization Bearer

### Test examples using cURL:
`curl http://localhost:8000/whoami`

`curl -H "Authorization: Bearer 0e31af88-e40d-4d1d-86e7-6f557d9ab28c" http://localhost:8000/whoami`

`curl -H "Cookie: GWTOKEN=0e31af88-e40d-4d1d-86e7-6f557d9ab28c" http://localhost:8000/whoami`