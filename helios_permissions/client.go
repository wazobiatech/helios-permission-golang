// Package helios_permissions — Helios HMAC client.
//
// Calls Helios's `GET /internal/permissions/:userId?tenantId=<uuid>`
// endpoint, which is HMAC-gated by SIGNATURE_SHARED_SECRET. The same
// contract the TS SDK's HeliosClient uses; this is the Go mirror.
//
// HMAC contract (matches the TS / Python SDKs' deviation from the
// canonical nexus-mcp contract — see CLAUDE.md / plan ZIN-4901e for
// the rationale):
//
//   payload  = METHOD + path + timestamp      // METHOD is uppercase
//   digest   = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
//   headers  = x-source-service, x-signature, x-timestamp
//   reject   if |now - timestamp| > 300s
//
// Path is signed WITHOUT the query string — Helios's internal
// hmac.ts verifier signs `req.method + req.path` (Express strips the
// query string and provides `req.method` lowercase). When Helios's
// verifier is fixed to canonical, this client updates in lockstep
// with the TS / Python SDKs.
//
// Response shape:
//
//   200 -> { status: "active", role, permissions, isActive, expiresAt }
//        | { status: "inactive", reason }
//        | { status: "not_a_member" }
//   404 -> { status: "not_a_member" }
//
// Any other non-2xx is a HeliosUnreachableError — the caller (the
// PermissionClient cache layer) treats that as "stale" and returns the
// cached value if present.

package helios_permissions

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HeliosUnreachableError is returned by HeliosClient when the
// upstream call fails for any reason — HTTP non-2xx, network error,
// HMAC verification failure on the response side (we don't sign
// responses, so this should not happen), or body parse error.
type HeliosUnreachableError struct {
	// StatusCode is the HTTP status, or 0 if the failure was network-
	// level (timeout, DNS, connection refused).
	StatusCode int
	// Reason is a short string identifying the failure mode.
	Reason string
	// Err is the underlying error, if any.
	Err error
}

func (e *HeliosUnreachableError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("helios unreachable (%s, status=%d): %v", e.Reason, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("helios unreachable (%s, status=%d)", e.Reason, e.StatusCode)
}

func (e *HeliosUnreachableError) Unwrap() error { return e.Err }

// MembershipResolution mirrors Helios's discriminated-union response.
// Exactly one of Role / Reason is set, depending on Status.
type MembershipResolution struct {
	// Status is one of "active" | "inactive" | "not_a_member".
	Status string `json:"status"`
	// Role is set when Status == "active".
	Role Role `json:"role,omitempty"`
	// Permissions is set when Status == "active".
	Permissions []Permission `json:"permissions,omitempty"`
	// IsActive is set when Status == "active".
	IsActive bool `json:"isActive,omitempty"`
	// ExpiresAt is set when Status == "active".
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// Reason is set when Status == "inactive". One of
	// "expired" | "soft_deleted".
	Reason string `json:"reason,omitempty"`
}

// HeliosClientOptions configures a HeliosClient.
type HeliosClientOptions struct {
	// BaseURL is the Helios service base URL, e.g. "https://helios.svc".
	BaseURL string
	// SignatureSharedSecret is the shared HMAC key. Required.
	SignatureSharedSecret string
	// SourceService is the value of the x-source-service header.
	// Defaults to "helios-permissions-go".
	SourceService string
	// HTTPClient is the underlying client. Defaults to a 2s-timeout
	// http.Client. Inject for tests (mock the transport) or for
	// connection pooling tuning.
	HTTPClient *http.Client
	// FetchTimeout defaults to 2s. The cache is on the hot path; a
	// Helios fetch is a fallback, not a blocking operation.
	FetchTimeout time.Duration
	// Now is injectable for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// HeliosClient calls Helios's internal permissions endpoint.
type HeliosClient struct {
	opts HeliosClientOptions
}

// NewHeliosClient wires the client.
func NewHeliosClient(opts HeliosClientOptions) *HeliosClient {
	if opts.BaseURL == "" {
		panic("helios_permissions: HeliosClientOptions.BaseURL is required")
	}
	if opts.SignatureSharedSecret == "" {
		panic("helios_permissions: HeliosClientOptions.SignatureSharedSecret is required")
	}
	if opts.SourceService == "" {
		opts.SourceService = "helios-permissions-go"
	}
	if opts.HTTPClient == nil {
		timeout := opts.FetchTimeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		opts.HTTPClient = &http.Client{Timeout: timeout}
	} else if opts.FetchTimeout > 0 {
		// Override the injected client's timeout if a FetchTimeout was
		// supplied. Helpful for callers that want a single knob.
		opts.HTTPClient.Timeout = opts.FetchTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &HeliosClient{opts: opts}
}

// FetchUserPermissions calls GET /internal/permissions/:userId?tenantId=<uuid>.
//
// Returns the parsed MembershipResolution on 200. Returns a
// MembershipResolution with Status == "not_a_member" on 404 (per
// Helios's documented contract — 404 is the "not a member" signal,
// not an error).
//
// Returns a *HeliosUnreachableError for any other failure (timeout,
// 5xx, parse error, etc).
func (c *HeliosClient) FetchUserPermissions(ctx context.Context, userID, tenantID string) (*MembershipResolution, error) {
	path := fmt.Sprintf("/internal/permissions/%s", userID)
	url := c.opts.BaseURL + path + "?tenantId=" + tenantID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &HeliosUnreachableError{Reason: "request_build", Err: err}
	}

	timestamp := strconv.FormatInt(c.opts.Now().Unix(), 10)
	signature := c.sign(http.MethodGet, path, timestamp)

	req.Header.Set("x-source-service", c.opts.SourceService)
	req.Header.Set("x-signature", signature)
	req.Header.Set("x-timestamp", timestamp)
	req.Header.Set("Accept", "application/json")

	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, &HeliosUnreachableError{Reason: "network", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Helios returns 404 for not_a_member. Per the SDK contract
		// (TS / Python), the caller treats this as a successful
		// resolution with status=not_a_member, not an error.
		return &MembershipResolution{Status: "not_a_member"}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &HeliosUnreachableError{
			StatusCode: resp.StatusCode,
			Reason:     "non_2xx",
			Err:        fmt.Errorf("body=%s", string(body)),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
	if err != nil {
		return nil, &HeliosUnreachableError{StatusCode: resp.StatusCode, Reason: "body_read", Err: err}
	}

	var resolution MembershipResolution
	if err := json.Unmarshal(body, &resolution); err != nil {
		return nil, &HeliosUnreachableError{StatusCode: resp.StatusCode, Reason: "body_parse", Err: err}
	}

	return &resolution, nil
}

// sign produces the lowercase-hex HMAC-SHA256 of the payload. Matches
// the TS / Python SDKs' deviation from the canonical nexus-mcp
// contract — see the package comment.
func (c *HeliosClient) sign(method, path, timestamp string) string {
	payload := method + path + timestamp
	mac := hmac.New(sha256.New, []byte(c.opts.SignatureSharedSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// IsHeliosUnreachableError is a type-narrowing helper for callers.
func IsHeliosUnreachableError(err error) bool {
	var h *HeliosUnreachableError
	return errors.As(err, &h)
}
