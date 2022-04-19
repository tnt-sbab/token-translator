package token_translator

import (
	"testing"
)

func TestIsValidUUID(t *testing.T) {
	table := []struct {
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

	for _, row := range table {
		valid := IsValidUUID(row.uuid)
		if valid != row.valid {
			t.Errorf("Token %s should result in %t", row.uuid, row.valid)
		}
	}
}
