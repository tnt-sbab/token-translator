package token_translator

import (
	"net/http"
	"testing"
)

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		uuid  string
		valid bool
	}{
		{"906f7fb0-bfd6-11ec-9d64-0242ac120002", true},   // valid uuidv1
		{"3bcce3fb-1849-4e13-bb4a-8922ffc46034", true},   // valid uuidv4
		{"3BCCE3FB-1849-4E13-BB4A-8922FFC46034", true},   // valid uuidv4 upper case
		{"3bcce3fba1849-4e13-bb4a-8922ffc46034", false},  // invalid first '-'
		{"3bcce3fb-1849a4e13-bb4a-8922ffc46034", false},  // invalid second '-'
		{"3bcce3fb-1849-4e13abb4a-8922ffc46034", false},  // invalid third '-'
		{"3bcce3fb-1849-4e13-bb4aa8922ffc46034", false},  // invalid fourth '-'
		{"3bcce3fb-1849-4e13-bb4a-8922ffc4603", false},   // too short
		{"3bcce3fb-1849-4e13-bb4a-8922ffc460344", false}, // too long
		{"3bcce3fb-/849-4e13-bb4a-8922ffc46034", false},  // one ascii below '0'
		{"3bcce3fb-:849-4e13-bb4a-8922ffc46034", false},  // one ascii above ')'
		{"3bcce3fb-@849-4e13-bb4a-8922ffc46034", false},  // one ascii below 'A'
		{"3bcce3fb-G849-4e13-bb4a-8922ffc46034", false},  // one ascii above 'F'
		{"3bcce3fb-`849-4e13-bb4a-8922ffc46034", false},  // one ascii below 'a'
		{"3bcce3fb-g849-4e13-bb4a-8922ffc46034", false},  // one ascii above 'f
		{"", false}, // empty
	}

	for _, row := range tests {
		valid := IsValidUUID(row.uuid)
		if valid != row.valid {
			t.Errorf("Token %s should result in %t", row.uuid, row.valid)
		}
	}
}

func TestParseTokenResponse(t *testing.T) {
	tests := []struct {
		json string
		jwt  string
		err  string
	}{
		{`{"token": "a.b.c"}`, "a.b.c", ""},
		{`{"token": "a.b.c", "message": "this is a custom error"}`, "", "this is a custom error"},
		{`{"message": "this is a custom error"}`, "", "this is a custom error"},
		{`{"message": ""}`, "", "empty token response"},
		{`{"token": ""}`, "", "empty token response"},
		{`{}`, "", "empty token response"},
		{`{"unexpected": "property"}`, "", "empty token response"},
		{`{blabla`, "", "invalid character 'b' looking for beginning of object key string"},
		{``, "", "unexpected end of JSON input"},
	}
	for _, row := range tests {
		jwt, err := ParseTokenResponse([]byte(row.json))
		if jwt != row.jwt {
			t.Errorf("JSON %s should be parsed to jwt '%s' but was '%s'", row.json, row.jwt, jwt)
		}
		if (err != nil && err.Error() != row.err) || (err == nil && row.err != "") {
			t.Errorf("Expected JSON '%s' to generate error '%v' but was '%v'", row.json, row.err, err)
		}
	}
}

func TestExtractAuthorization(t *testing.T) {
	tests := []struct {
		req           *http.Request
		authorization string
	}{
		{createRequest(httpHeader{"Authorization", "Bearer 1"}), "1"},
		{createRequest(httpHeader{"Authorization", "Bearer 034821a2-6318-48f0-a0d5-b130104c63d1"}), "034821a2-6318-48f0-a0d5-b130104c63d1"},
		{createRequest(httpHeader{"Authorization", "034821a2-6318-48f0-a0d5-b130104c63d1"}), "034821a2-6318-48f0-a0d5-b130104c63d1"},
		{createRequest(httpHeader{"Authorization", "2"}), "2"},
		{createRequest(httpHeader{"Cookie", "GWTOKEN=034821a2-6318-48f0-a0d5-b130104c63d1"}), "034821a2-6318-48f0-a0d5-b130104c63d1"},
		{createRequest(httpHeader{"AnotherHeader", "034821a2-6318-48f0-a0d5-b130104c63d1"}), ""},
		{createRequest(
			httpHeader{"Authorization", "Bearer 1f8a367e-9b24-4a9b-a739-7fc539fbebaa"},
			httpHeader{"Cookie", "GWTOKEN=034821a2-6318-48f0-a0d5-b130104c63d1"},
		), "1f8a367e-9b24-4a9b-a739-7fc539fbebaa"}, // Authorization header over GWTOKEN Cookie value
		{createRequest(), ""},
	}
	for _, row := range tests {
		authorization, _ := ExtractAuthorization(row.req)
		if authorization != row.authorization {
			t.Errorf("Extected request to generate authorization '%s' but was '%s'", row.authorization, authorization)
		}
	}

}

type httpHeader struct {
	key   string
	value string
}

func createRequest(headers ...httpHeader) *http.Request {
	req, _ := http.NewRequest("GET", "/api/test", nil)
	for _, header := range headers {
		req.Header.Add(header.key, header.value)
	}
	return req
}
