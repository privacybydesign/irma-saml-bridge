package disclosure

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claims parses JSON the way a verified JWT hands it over.
func claims(t *testing.T, s string) map[string]any {
	t.Helper()

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &out))

	return out
}

func TestFromClaims(t *testing.T) {
	d, err := FromClaims(claims(t, `{
		"token": "KzxuWKwL5KGLKr4uerws",
		"status": "DONE",
		"type": "disclosing",
		"proofStatus": "VALID",
		"disclosed": [
			[{"rawvalue": "user@example.com", "id": "pbdf.sidn-pbdf.email.email", "status": "PRESENT"},
			 {"rawvalue": "example.com", "id": "pbdf.sidn-pbdf.email.domain", "status": "PRESENT"}],
			[{"rawvalue": "+31612345678", "id": "pbdf.sidn-pbdf.mobilenumber.mobilenumber", "status": "PRESENT"}]
		]
	}`))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"pbdf.sidn-pbdf.email.email":               "user@example.com",
		"pbdf.sidn-pbdf.email.domain":              "example.com",
		"pbdf.sidn-pbdf.mobilenumber.mobilenumber": "+31612345678",
	}, d.Attributes)
	assert.Equal(t, "VALID", d.ProofStatus)
	assert.Equal(t, "KzxuWKwL5KGLKr4uerws", d.Token)
}

// A conjunction counts only when every attribute in it is PRESENT.
func TestFromClaimsDropsIncompleteConjunctions(t *testing.T) {
	d, err := FromClaims(claims(t, `{
		"proofStatus": "VALID",
		"disclosed": [
			[{"rawvalue": "a", "id": "s.i.c.a", "status": "PRESENT"}, {"rawvalue": "b", "id": "s.i.c.b", "status": "EXTRA"}],
			[{"rawvalue": null, "id": "s.i.c.c", "status": "NULL"}],
			[{"rawvalue": "d", "id": "s.i.c.d"}],
			[{"rawvalue": "e", "id": "s.i.c.e", "status": "PRESENT"}],
			[{"id": "s.i.c.f", "status": "PRESENT"}],
			[{"rawvalue": 7, "id": "s.i.c.g", "status": "PRESENT"}],
			[]
		]
	}`))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"s.i.c.e": "e"}, d.Attributes)
	assert.Empty(t, d.Token)
}

// Counterpart of AssertControllerTest.reportTestMalformedException.
func TestFromClaimsMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"string":            `{"disclosed": "malformedClaim"}`,
		"missing":           `{"proofStatus": "VALID"}`,
		"null":              `{"disclosed": null}`,
		"object":            `{"disclosed": {}}`,
		"list of strings":   `{"disclosed": ["a"]}`,
		"list of objects":   `{"disclosed": [{"id": "a"}]}`,
		"attribute a list":  `{"disclosed": [[["a"]]]}`,
		"attribute a value": `{"disclosed": [["a"]]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FromClaims(claims(t, body))
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func TestFromClaimsEmptyDisclosure(t *testing.T) {
	d, err := FromClaims(claims(t, `{"disclosed": [], "proofStatus": 5, "token": ["x"]}`))
	require.NoError(t, err)

	assert.Empty(t, d.Attributes)
	assert.Empty(t, d.ProofStatus)
	assert.Empty(t, d.Token)
}

func TestFulfills(t *testing.T) {
	d := &Disclosure{Attributes: map[string]string{"a": "1", "b": "2", "c": "3"}}

	tests := map[string]struct {
		condiscon [][][]string
		want      bool
	}{
		"single attribute":         {[][][]string{{{"a"}}}, true},
		"missing attribute":        {[][][]string{{{"x"}}}, false},
		"conjunction":              {[][][]string{{{"a", "b"}}}, true},
		"conjunction one missing":  {[][][]string{{{"a", "x"}}}, false},
		"disjunction second":       {[][][]string{{{"x"}, {"b"}}}, true},
		"disjunction none":         {[][][]string{{{"x"}, {"y"}}}, false},
		"all disjunctions":         {[][][]string{{{"a"}}, {{"b"}}, {{"x"}, {"c"}}}, true},
		"one disjunction fails":    {[][][]string{{{"a"}}, {{"x"}}}, false},
		"empty condiscon":          {[][][]string{}, true},
		"empty disjunction":        {[][][]string{{}}, false},
		"empty conjunction":        {[][][]string{{{}}}, true},
		"identifier is exact":      {[][][]string{{{"A"}}}, false},
		"prefix is not enough":     {[][][]string{{{"a.b"}}}, false},
		"same attribute requested": {[][][]string{{{"a", "a"}}}, true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, d.Fulfills(tt.condiscon))
		})
	}

	// Nothing disclosed fulfils nothing that asks for something.
	assert.False(t, (&Disclosure{}).Fulfills([][][]string{{{"a"}}}))
}
