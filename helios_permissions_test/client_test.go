package helios_permissions_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

// frozenNow returns a deterministic clock for HMAC tests.
func frozenNow() func() time.Time {
	t := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// fakeSigHeaders signs the same way helios-permissions (and the TS /
// Python SDKs) signs requests.
func fakeSigHeaders(secret, method, path, timestamp string) (sig string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(method + path + timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

// TestFetchUserPermissions_HMAC_Headers_And_PathNoQuery verifies
// the wire format: GET, headers set, path signed WITHOUT query.
func TestFetchUserPermissions_HMAC_Headers_And_PathNoQuery(t *testing.T) {
	const (
		secret = "test-secret"
		uid    = "user-123"
		tid    = "tenant-abc"
	)
	var (
		gotMethod     string
		gotPath       string
		gotQuery      string
		gotSig        string
		gotTS         string
		gotSourceSvc  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotSig = r.Header.Get("x-signature")
		gotTS = r.Header.Get("x-timestamp")
		gotSourceSvc = r.Header.Get("x-source-service")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"active","role":"EDITOR","permissions":["athens:project:view"]}`)
	}))
	defer srv.Close()

	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: secret,
		SourceService:        "helios-permissions-go-test",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})

	res, err := c.FetchUserPermissions(context.Background(), uid, tid)
	if err != nil {
		t.Fatalf("FetchUserPermissions: %v", err)
	}
	if res == nil || res.Status != "active" {
		t.Fatalf("expected active resolution, got %+v", res)
	}

	if gotMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if !strings.HasPrefix(gotPath, "/internal/permissions/") || !strings.HasSuffix(gotPath, "/"+uid) {
		t.Fatalf("path = %q, want /internal/permissions/%s", gotPath, uid)
	}
	if gotQuery != "tenantId="+tid {
		t.Fatalf("query = %q, want tenantId=%s", gotQuery, tid)
	}
	if gotSourceSvc != "helios-permissions-go-test" {
		t.Fatalf("x-source-service = %q", gotSourceSvc)
	}
	// Verify the signature: method UPPER + path (no query) + timestamp.
	tsInt, err := strconv.ParseInt(gotTS, 10, 64)
	if err != nil {
		t.Fatalf("x-timestamp not an int: %v", err)
	}
	wantSig := fakeSigHeaders(secret, http.MethodGet, gotPath, strconv.FormatInt(tsInt, 10))
	if !hmac.Equal([]byte(gotSig), []byte(wantSig)) {
		t.Fatalf("signature mismatch: got %q want %q (path signed = %q)", gotSig, wantSig, gotPath)
	}
}

// TestFetchUserPermissions_404_IsNotMember — Helios returns 404 for
// not_a_member; the client should NOT treat that as an error.
func TestFetchUserPermissions_404_IsNotMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	}))
	defer srv.Close()

	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	res, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if err != nil {
		t.Fatalf("404 should be a successful not_a_member resolution, got error: %v", err)
	}
	if res == nil || res.Status != "not_a_member" {
		t.Fatalf("expected not_a_member status, got %+v", res)
	}
}

// TestFetchUserPermissions_500_IsUnreachable — non-2xx (and not 404)
// becomes a HeliosUnreachableError.
func TestFetchUserPermissions_500_IsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	}))
	defer srv.Close()

	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	_, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !hp.IsHeliosUnreachableError(err) {
		t.Fatalf("expected *HeliosUnreachableError, got %T: %v", err, err)
	}
}

// TestFetchUserPermissions_NetworkError_IsUnreachable — closed
// server should yield a HeliosUnreachableError with StatusCode=0.
func TestFetchUserPermissions_NetworkError_IsUnreachable(t *testing.T) {
	// Bind a listener and immediately close it so the address is
	// guaranteed to refuse connections.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              url,
		SignatureSharedSecret: "x",
		HTTPClient:           &http.Client{Timeout: 200 * time.Millisecond},
		Now:                  frozenNow(),
	})
	_, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if err == nil {
		t.Fatal("expected error on network failure")
	}
	if !hp.IsHeliosUnreachableError(err) {
		t.Fatalf("expected *HeliosUnreachableError, got %T: %v", err, err)
	}
}

// TestFetchUserPermissions_ParsesAllFields asserts the response
// shape matches the Helios contract: status, role, permissions,
// isActive, expiresAt.
func TestFetchUserPermissions_ParsesAllFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"status": "active",
			"role": "ADMIN",
			"permissions": ["athens:project:view", "athens:project:update"],
			"isActive": true,
			"expiresAt": "2027-01-01T00:00:00Z"
		}`)
	}))
	defer srv.Close()
	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	res, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "active" || res.Role != hp.RoleAdmin || !res.IsActive {
		t.Fatalf("unexpected resolution: %+v", res)
	}
	if len(res.Permissions) != 2 {
		t.Fatalf("expected 2 perms, got %d", len(res.Permissions))
	}
	if res.ExpiresAt == nil || res.ExpiresAt.Year() != 2027 {
		t.Fatalf("expiresAt not parsed: %v", res.ExpiresAt)
	}
}

// TestFetchUserPermissions_InactiveReason parses status=inactive
// with a reason.
func TestFetchUserPermissions_InactiveReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"inactive","reason":"expired"}`)
	}))
	defer srv.Close()
	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	res, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "inactive" || res.Reason != "expired" {
		t.Fatalf("unexpected: %+v", res)
	}
}

// TestFetchUserPermissions_400TriggersUnreachable makes sure 4xx
// other than 404 also becomes HeliosUnreachableError (defensive —
// the contract says only 200/404 should happen).
func TestFetchUserPermissions_400TriggersUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"bad request"}`)
	}))
	defer srv.Close()
	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	_, err := c.FetchUserPermissions(context.Background(), "u", "t")
	if !hp.IsHeliosUnreachableError(err) {
		t.Fatalf("expected unreachable error, got %T: %v", err, err)
	}
}

// TestHeliosUnreachableError_Unwrap makes errors.Is / errors.As work
// against the wrapped cause.
func TestHeliosUnreachableError_Unwrap(t *testing.T) {
	root := errors.New("network down")
	h := &hp.HeliosUnreachableError{StatusCode: 0, Reason: "network", Err: root}
	if !errors.Is(h, root) {
		t.Fatal("errors.Is should walk Unwrap chain")
	}
}

// TestDefaultSourceService confirms the default is set when SourceService
// is empty.
func TestDefaultSourceService(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("x-source-service")
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	}))
	defer srv.Close()
	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	_, _ = c.FetchUserPermissions(context.Background(), "u", "t")
	if got != "helios-permissions-go" {
		t.Fatalf("default source service = %q, want helios-permissions-go", got)
	}
}

// TestHeliosUnreachableError_Message sanity-checks the error
// formatting for the two branches (with and without cause).
func TestHeliosUnreachableError_Message(t *testing.T) {
	withCause := (&hp.HeliosUnreachableError{StatusCode: 502, Reason: "non_2xx", Err: errors.New("x")}).Error()
	if !strings.Contains(withCause, "502") || !strings.Contains(withCause, "non_2xx") || !strings.Contains(withCause, "x") {
		t.Fatalf("missing fields: %s", withCause)
	}
	noCause := (&hp.HeliosUnreachableError{StatusCode: 0, Reason: "network"}).Error()
	if !strings.Contains(noCause, "network") {
		t.Fatalf("missing reason: %s", noCause)
	}
}

// TestFetchUserPermissions_ContextCancelled is a quick defense-in-
// depth test that a cancelled context yields an error.
func TestFetchUserPermissions_ContextCancelled(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"active","role":"VIEWER","permissions":[]}`)
	}))
	defer srv.Close()
	c := hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              srv.URL,
		SignatureSharedSecret: "x",
		HTTPClient:           srv.Client(),
		Now:                  frozenNow(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.FetchUserPermissions(ctx, "u", "t")
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	_ = atomic.LoadInt32(&hits)
}
