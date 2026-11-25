package ledger

import (
	"time"
)

const (
	// flowKeyPrefix namespaces NATS KV flow records; URL-safe nonces use valid key characters.
	flowKeyPrefix = "oauthflow.v2."
	// minKeyTTL is the smallest per-key TTL NATS accepts.
	minKeyTTL = time.Second
)

type flowState string

const (
	// flowPending awaits the application browser's authorization.
	flowPending    flowState = "pending"
	flowAuthorized flowState = "authorized"
	// flowCaptured holds the session and awaits Redeem.
	flowCaptured flowState = "captured"
	// flowBurned is terminal, whether consumed or rejected for a binding failure.
	flowBurned flowState = "burned"
)

// flowRecord stores a nonce's state, bindings, and session data.
type flowRecord struct {
	State              flowState `json:"state"`
	TargetSubdomain    string    `json:"target_subdomain"`
	TargetURL          string    `json:"target_url"`
	BrowserBindingHash []byte    `json:"browser_binding_hash"`
	AuthProofHash      []byte    `json:"auth_proof_hash,omitempty"`
	RedeemCodeHash     []byte    `json:"redeem_code_hash,omitempty"`
	SessionCookie      string    `json:"session_cookie,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// MintRequest supplies the destination for a new flow.
type MintRequest struct {
	TargetSubdomain string
	TargetURL       string
}

// MintResult returns the nonce and browser-binding secret. Only the secret's hash is stored.
type MintResult struct {
	Nonce         string
	BindingSecret string
}

// CaptureRequest supplies the auth-domain session and auth proof.
type CaptureRequest struct {
	Nonce         string
	Authority     string
	SessionCookie string
	AuthProof     string
}

// CaptureStart contains the target authority, auth proof, and its hash as a challenge.
type CaptureStart struct {
	TargetAuthority string
	AuthProof       string
	Challenge       string
}

// AuthorizeRequest supplies the application host, browser secret, and auth challenge.
type AuthorizeRequest struct {
	Nonce         string
	Authority     string
	BindingSecret string
	Challenge     string
}

// CaptureResponse identifies the target host and the one-time code the auth page redeems
// there. The code is never placed in a URL the target host navigates to.
type CaptureResponse struct {
	TargetSubdomain string
	RedeemCode      string
}

// RedeemRequest supplies the browser proof and target request binding.
type RedeemRequest struct {
	Nonce         string
	Authority     string
	BindingSecret string
	Code          string
}

// RedeemResponse returns the handle of the host session issued for the target and the
// intended destination, without exposing the captured oauth2-proxy session in the response.
type RedeemResponse struct {
	SessionHandle string
	TargetURL     string
}
