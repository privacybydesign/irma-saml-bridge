// Package disclosure reads the result of an IRMA disclosure session and
// checks it against what was asked for.
package disclosure

import (
	"errors"
	"maps"
	"slices"
)

// ErrMalformed is returned when the session result does not have the shape
// the IRMA server documents.
var ErrMalformed = errors.New("disclosure: malformed session result")

const (
	statusPresent = "PRESENT"

	// ProofValid is the proofStatus of a disclosure the IRMA server verified.
	ProofValid = "VALID"
)

// Disclosure is the part of an IRMA session result the bridge uses. See
// https://irma.app/docs/api-irma-server/#get-session-token-result.
type Disclosure struct {
	// Attributes holds the raw value of each disclosed attribute, by
	// attribute identifier.
	Attributes map[string]string

	// ProofStatus is VALID when the IRMA server verified the proofs.
	ProofStatus string

	// Token is the requestor token of the session.
	Token string
}

// FromClaims reads a disclosure from the claims of a session result JWT.
//
// "disclosed" is a list with one list of attributes per conjunction the user
// chose. A conjunction is taken only when all its attributes are PRESENT, as
// the Java service did; one with an absent or extra attribute is dropped.
func FromClaims(claims map[string]any) (*Disclosure, error) {
	cons, ok := claims["disclosed"].([]any)
	if !ok {
		return nil, ErrMalformed
	}

	d := &Disclosure{Attributes: map[string]string{}}

	for _, c := range cons {
		con, ok := c.([]any)
		if !ok {
			return nil, ErrMalformed
		}

		present := make(map[string]string, len(con))
		complete := true

		for _, a := range con {
			attribute, ok := a.(map[string]any)
			if !ok {
				return nil, ErrMalformed
			}

			id, hasID := attribute["id"].(string)
			value, hasValue := attribute["rawvalue"].(string)

			if status, _ := attribute["status"].(string); status != statusPresent || !hasID || !hasValue {
				complete = false

				break
			}

			present[id] = value
		}

		if !complete {
			continue
		}

		maps.Copy(d.Attributes, present)
	}

	d.ProofStatus, _ = claims["proofStatus"].(string)
	d.Token, _ = claims["token"].(string)

	return d, nil
}

// Fulfills reports whether the disclosed attributes satisfy the condiscon:
// for every disjunction, at least one conjunction whose attributes were all
// disclosed.
func (d *Disclosure) Fulfills(condiscon [][][]string) bool {
	for _, discon := range condiscon {
		if !d.fulfillsDiscon(discon) {
			return false
		}
	}

	return true
}

func (d *Disclosure) fulfillsDiscon(discon [][]string) bool {
	return slices.ContainsFunc(discon, d.fulfillsCon)
}

func (d *Disclosure) fulfillsCon(con []string) bool {
	for _, id := range con {
		if _, ok := d.Attributes[id]; !ok {
			return false
		}
	}

	return true
}
