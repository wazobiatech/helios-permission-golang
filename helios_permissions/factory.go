// Package helios_permissions — Create factory.
//
// Create wires the three layers (HeliosClient, RedisPermissionCache,
// PermissionClient) and owns the Redis connection lifecycle. Most
// services should use Create and pass the returned Client around —
// the underlying *redis.Client and the *HeliosClient are kept
// private.
//
// Create is the only public constructor in v1. Direct NewClient /
// NewHeliosClient / NewRedisPermissionCache usage is for tests
// and for services that want to inject their own cache or Helios
// transport (e.g. for hermetic unit tests).
//
// Example:
//
//	r, err := helios_permissions.Create(helios_permissions.CreateOptions{
//	    HeliosBaseURL:         os.Getenv("HELIOS_BASE_URL"),
//	    SignatureSharedSecret: os.Getenv("SIGNATURE_SHARED_SECRET"),
//	    RedisURL:              os.Getenv("PERMISSION_REDIS_URL"),
//	})
//	if err != nil { log.Fatal(err) }
//	defer r.Close()
//
//	allowed, err := r.Client.CallerHasPermission(ctx, userID, tenantID,
//	    helios_permissions.PermissionAthensProjectView)

package helios_permissions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// CreateOptions configures Create.
type CreateOptions struct {
	// HeliosBaseURL is the Helios service base URL. Required.
	HeliosBaseURL string
	// SignatureSharedSecret is the shared HMAC key for Helios auth. Required.
	SignatureSharedSecret string
	// HeliosSourceService overrides the x-source-service header value.
	// Defaults to "helios-permissions-go".
	HeliosSourceService string
	// RedisURL is the connection URL for the shared permission cache.
	// If Redis is non-nil, this is ignored.
	RedisURL string
	// Redis is an optional pre-built go-redis client. If non-nil, the
	// factory will NOT call Close on it (the caller owns the lifecycle).
	// If nil and RedisURL is set, the factory builds its own client
	// and owns the lifecycle (Close closes it).
	Redis *redis.Client
	// CacheTTLSeconds defaults to 60. The TTL is the safety net when
	// invalidation fails — it bounds cache staleness.
	CacheTTLSeconds int
	// Logger defaults to SilentLogger. Inject a structured logger in
	// production for the warn/error paths.
	Logger Logger
	// StaleOnError defaults to true (fail-closed: allow stale on
	// Helios error so a brief Helios outage doesn't lock everyone out).
	StaleOnError *bool
	// FetchTimeout defaults to 2s. The cache is on the hot path; a
	// Helios fetch is a fallback, not a blocking operation.
	FetchTimeout time.Duration
	// HTTPClient is the underlying *http.Client for the Helios
	// transport. Defaults to a 2s-timeout client.
	HTTPClient *http.Client
}

// Result is what Create returns. The caller uses Client for
// permission checks and calls Close on shutdown. Redis and Helios
// are exposed for advanced use cases (e.g. metrics / health checks).
type Result struct {
	// Client is the public facade.
	Client Client
	// Redis is the *redis.Client the cache is using. It is nil only
	// if the caller never configured Redis (which is a misconfiguration
	// — the SDK requires a cache in production).
	Redis *redis.Client
	// Helios is the underlying HeliosClient. Exposed for tests and
	// advanced use cases (e.g. wiring a custom middleware).
	Helios *HeliosClient
	// Close releases any resources Create owns. If the caller injected
	// its own *redis.Client, Close is a no-op for the Redis side
	// (the caller owns the lifecycle). It is always safe to defer
	// Close() — it is idempotent.
	Close func() error
}

// Create wires the three layers and returns a Result. It returns
// an error if any required option is missing or if the Redis
// connection fails to ping.
func Create(opts CreateOptions) (*Result, error) {
	if opts.HeliosBaseURL == "" {
		return nil, errors.New("helios_permissions: CreateOptions.HeliosBaseURL is required")
	}
	if opts.SignatureSharedSecret == "" {
		return nil, errors.New("helios_permissions: CreateOptions.SignatureSharedSecret is required")
	}
	if opts.Redis == nil && opts.RedisURL == "" {
		return nil, errors.New("helios_permissions: one of CreateOptions.Redis or CreateOptions.RedisURL is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = SilentLogger()
	}

	// Redis — build or accept injection.
	ownsRedis := false
	redisClient := opts.Redis
	if redisClient == nil {
		opts, err := redis.ParseURL(opts.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("helios_permissions: parse RedisURL: %w", err)
		}
		redisClient = redis.NewClient(opts)
		ownsRedis = true
	}

	// Ping Redis to fail fast on misconfiguration. A 2s timeout is
	// plenty — Redis should respond in <1ms on a healthy cluster.
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		if ownsRedis {
			_ = redisClient.Close()
		}
		return nil, fmt.Errorf("helios_permissions: Redis ping failed: %w", err)
	}

	// Cache — wrap the Redis client.
	cache := NewRedisPermissionCache(RedisCacheOptions{
		Client:     redisClient,
		TTLSeconds: opts.CacheTTLSeconds,
		Logger:     logger,
	})

	// HeliosClient.
	heliosOpts := HeliosClientOptions{
		BaseURL:              opts.HeliosBaseURL,
		SignatureSharedSecret: opts.SignatureSharedSecret,
		SourceService:        opts.HeliosSourceService,
		HTTPClient:           opts.HTTPClient,
		FetchTimeout:         opts.FetchTimeout,
	}
	helios := NewHeliosClient(heliosOpts)

	// PermissionClient.
	client, err := NewClient(ClientOptions{
		Cache:        cache,
		Helios:       helios,
		StaleOnError: opts.StaleOnError,
		Logger:       logger,
	})
	if err != nil {
		if ownsRedis {
			_ = redisClient.Close()
		}
		return nil, err
	}

	// Close: only close the Redis client if we built it ourselves.
	var closed bool
	close := func() error {
		if closed {
			return nil
		}
		closed = true
		if ownsRedis {
			return redisClient.Close()
		}
		return nil
	}

	return &Result{
		Client: client,
		Redis:  redisClient,
		Helios: helios,
		Close:  close,
	}, nil
}
