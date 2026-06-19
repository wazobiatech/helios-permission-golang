package helios_permissions_test

import (
	"context"
	"strings"
	"testing"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestCreate_RequiresHeliosBaseURL(t *testing.T) {
	_, err := hp.Create(hp.CreateOptions{
		SignatureSharedSecret: "x",
		RedisURL:              "redis://127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("expected error for missing HeliosBaseURL")
	}
}

func TestCreate_RequiresSignatureSharedSecret(t *testing.T) {
	_, err := hp.Create(hp.CreateOptions{
		HeliosBaseURL: "https://helios.example",
		RedisURL:      "redis://127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("expected error for missing signature secret")
	}
}

func TestCreate_RequiresRedisOrURL(t *testing.T) {
	_, err := hp.Create(hp.CreateOptions{
		HeliosBaseURL:         "https://helios.example",
		SignatureSharedSecret: "x",
	})
	if err == nil {
		t.Fatal("expected error when neither Redis nor RedisURL is set")
	}
}

// TestCreate_WithInjectedRedis: caller owns the *redis.Client;
// Close() must NOT close it.
func TestCreate_WithInjectedRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Skipf("miniredis not available: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	r, err := hp.Create(hp.CreateOptions{
		HeliosBaseURL:         "https://helios.example",
		SignatureSharedSecret: "x",
		Redis:                 rdb,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.Client == nil {
		t.Fatal("Client should be non-nil")
	}
	if r.Redis != rdb {
		t.Fatal("Redis should be the injected client")
	}
	// Close should NOT close the injected client.
	_ = r.Close()
	// Pinging the still-open client should succeed.
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("injected client should still be open after Close: %v", err)
	}
}

// TestCreate_BuildsOwnRedisAndClosesIt: factory owns the lifecycle
// when given a URL; Close closes the client.
func TestCreate_BuildsOwnRedisAndClosesIt(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Skipf("miniredis not available: %v", err)
	}
	defer mr.Close()
	r, err := hp.Create(hp.CreateOptions{
		HeliosBaseURL:         "https://helios.example",
		SignatureSharedSecret: "x",
		RedisURL:              "redis://" + mr.Addr(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.Redis == nil {
		t.Fatal("Redis should be non-nil")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Pinging after close should fail.
	if err := r.Redis.Ping(context.Background()).Err(); err == nil {
		t.Fatal("ping after Close should fail (factory-owned client must be closed)")
	}
	// Close is idempotent.
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestCreate_FailsOnUnreachableRedis: factory should fail fast with
// a clear error when Redis is unreachable.
func TestCreate_FailsOnUnreachableRedis(t *testing.T) {
	// Reserve an addr and close the listener so the port is unlikely
	// to be used. miniredis guarantees a free port; we just don't
	// start the server.
	mr, err := miniredis.Run()
	if err != nil {
		t.Skipf("miniredis not available: %v", err)
	}
	addr := mr.Addr()
	mr.Close()

	_, err = hp.Create(hp.CreateOptions{
		HeliosBaseURL:         "https://helios.example",
		SignatureSharedSecret: "x",
		RedisURL:              "redis://" + addr,
	})
	if err == nil {
		t.Fatal("expected Create to fail when Redis is unreachable")
	}
	if !strings.Contains(err.Error(), "Redis") {
		t.Fatalf("error should mention Redis, got: %v", err)
	}
}

// TestCreate_BadRedisURL: parse error path.
func TestCreate_BadRedisURL(t *testing.T) {
	_, err := hp.Create(hp.CreateOptions{
		HeliosBaseURL:         "https://helios.example",
		SignatureSharedSecret: "x",
		RedisURL:              "::not a url::",
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
}
