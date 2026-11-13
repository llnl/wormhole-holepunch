package ledger

import (
	"time"
)

// flowKeyPrefix namespaces flow records in the session store. NATS KV keys are limited to
// [-/_=.a-zA-Z0-9], which nonces (unpadded URL-safe base64) always satisfy.
const flowKeyPrefix = "oauthflow.v1."

type flowState string

const (
	// flowPending is minted by Holepunch Auth, awaiting Capture.
	flowPending flowState = "pending"
	// flowCaptured holds the oauth2-proxy session cookie, awaiting Redeem.
	flowCaptured flowState = "captured"
	// flowBurned has been consumed (successfully or by a binding failure) and can never
	// be used again.
	flowBurned flowState = "burned"
)

// flowRecord is the single KV record tracking a nonce through the middleware flow.
type flowRecord struct {
	State              flowState `json:"state"`
	ClientIP           string    `json:"client_ip"`
	TargetScheme       string    `json:"target_scheme"`
	TargetSubdomain    string    `json:"target_subdomain"`
	TargetURL          string    `json:"target_url"`
	BrowserBindingHash []byte    `json:"browser_binding_hash"`
	SessionCookie      string    `json:"session_cookie,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// MintRequest binds a new flow to the initiating client and intended destination.
type MintRequest struct {
	ClientIP        string
	TargetScheme    string
	TargetSubdomain string
	TargetURL       string
}

// MintResult provides the nonce and the secret to place in the browser's binding cookie.
// Only the hash of BindingSecret is persisted.
type MintResult struct {
	Nonce         string
	BindingSecret string
}

// CaptureRequest is made by the callback at the auth domain.
type CaptureRequest struct {
	Nonce         string
	ClientIP      string
	Authority     string
	SessionCookie string
}

// CaptureResponse directs the browser to the target sub-domain callback.
type CaptureResponse struct {
	TargetSubdomain string
	CallbackURL     string
}

// RedeemRequest is made by the callback at the target sub-domain.
type RedeemRequest struct {
	Nonce         string
	ClientIP      string
	Authority     string
	BindingSecret string
}

// RedeemResponse provides the captured session cookie and the user's intended destination.
type RedeemResponse struct {
	SessionCookie string
	TargetURL     string
}
