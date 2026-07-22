// Package wormhole supports data structures and helpers functions relating
// to token and registry services.
package wormhole

import (
	"encoding/json"
	"time"
)

// TokenContext organize core details regarding a user's request and any
// related assertions in the payload from a validated token.
type TokenContext struct {
	// WAT is the raw request token (Wormhole Access Token) provided by the user.
	WAT string `json:"token"`
	// TokenID is the proposed unique identification derived from the raw WAT.
	// Payload for the token service issued JWT.
	TokenID string       `json:"token_id"`
	Payload TokenPayload `json:"payload"`
}

type TokenPayload struct {
	// Username (unix) for the token owner.
	Username string `json:"sub"`
	// Groups lists all unix groups the user belongs too.
	Groups []string `json:"groups"`
	// DUID offers the users DOE Unique Identifier.
	DUID string `json:"duid"`
	// ParentID optionally identifies the parent, implying this is a subtoken.
	ParentID string `json:"parent_id"`
	// ExternalID optionally ties the token to a unique community_id.
	ExternalID string `json:"external_id"`
	// Exp the expiration for the token service issued JWT.
	Exp FloatTime `json:"exp"`
	// TokenID for the request token or sessions.
	TokenID string `json:"token_id"`
}

//

type FloatTime struct {
	time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (ft *FloatTime) UnmarshalJSON(data []byte) error {
	var floatTimestamp float64

	if err := json.Unmarshal(data, &floatTimestamp); err != nil {
		return err
	}

	seconds := int64(floatTimestamp)                                // Extract seconds part
	nanoseconds := int64((floatTimestamp - float64(seconds)) * 1e9) // Extract fractional nanoseconds
	ft.Time = time.Unix(seconds, nanoseconds)

	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (ft FloatTime) MarshalJSON() ([]byte, error) {
	floatTimestamp := float64(ft.Unix()) + float64(ft.Nanosecond())/1e9

	return json.Marshal(floatTimestamp)
}
