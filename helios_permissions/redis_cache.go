// Package helios_permissions — Redis-backed PermissionCache.
//
// Key shape (must match Helios's permission-cache.service.ts and the TS
// SDK's RedisPermissionCache): `helios:perms:{userId}:{tenantId}` ->
// JSON array of permission strings. Drift here would silently break
// every cross-language consumer.
//
// Connection: caller-owned *redis.Client. The factory in factory.go
// either builds one or accepts an injection. The cache does NOT manage
// the connection lifecycle — the caller (typically a service's main()
// or DI container) is responsible for Close().
//
// Invalidation patterns:
//
//   Invalidate(userId, tenantId)   -> DEL helios:perms:{userId}:{tenantId}
//   InvalidateTenant(tenantId)     -> SCAN MATCH helios:perms:*:{tenantId} DEL
//
// SCAN is non-blocking; KEYS would block the Redis event loop on a
// large keyspace.
//
// Error handling — best-effort, fail open:
//
//   - Get failures:  log warn + return nil (caller falls through to Helios).
//   - Set failures:  log warn + return error. Caller decides — for the
//                    in-flight repopulate path, swallowing is fine.
//   - WriteThrough:  log warn + return error. Helios's own writeThrough
//                    logs + swallows because the Prisma mutation has
//                    already committed; the cache will heal via TTL.
//   - Invalidate:    log error + return error. Stale data has no
//                    automatic recovery except TTL expiry. Operators
//                    need visibility.

package helios_permissions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

const (
	// KeyPrefix is the cache key prefix. Must match Helios's writer.
	KeyPrefix = "helios:perms:"

	// DefaultCacheTTLSeconds is the default TTL. Helios's writer uses
	// the same value (60s) — the TTL is the safety net when
	// invalidation fails.
	DefaultCacheTTLSeconds = 60

	// scanBatchSize balances round-trip count vs cursor overhead.
	scanBatchSize = 100
)

// Logger is the minimal logging surface the SDK needs. The host
// service injects its logger; the SDK does not log to stdout by
// default (a misbehaving cache layer should not pollute the host's
// logs).
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// silentLogger is the default. All methods are no-ops.
type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

// SilentLogger returns a no-op logger. Useful for tests and for
// services that don't want the SDK to log.
func SilentLogger() Logger { return silentLogger{} }

// ConsoleLogger logs via the standard log package. Convenience for
// small services that don't have a structured logger yet.
type ConsoleLogger struct{}

func (ConsoleLogger) Debug(msg string, kv ...any) {
	log.Println("[DEBUG]", fmt.Sprintf(msg, kv...))
}
func (ConsoleLogger) Info(msg string, kv ...any) {
	log.Println("[INFO]", fmt.Sprintf(msg, kv...))
}
func (ConsoleLogger) Warn(msg string, kv ...any) {
	log.Println("[WARN]", fmt.Sprintf(msg, kv...))
}
func (ConsoleLogger) Error(msg string, kv ...any) {
	log.Println("[ERROR]", fmt.Sprintf(msg, kv...))
}

// RedisPermissionCache is the production PermissionCache impl.
type RedisPermissionCache struct {
	rdb       *redis.Client
	ttl       int
	keyPrefix string
	logger    Logger
}

// RedisCacheOptions configures a RedisPermissionCache.
type RedisCacheOptions struct {
	// Client is the configured go-redis client. Required.
	Client *redis.Client
	// TTLSeconds defaults to DefaultCacheTTLSeconds.
	TTLSeconds int
	// KeyPrefix defaults to KeyPrefix. Override only for tests.
	KeyPrefix string
	// Logger defaults to SilentLogger. Inject a structured logger in
	// production for the warn/error paths.
	Logger Logger
}

// NewRedisPermissionCache wires the cache. The caller owns the
// *redis.Client and is responsible for Close().
func NewRedisPermissionCache(opts RedisCacheOptions) *RedisPermissionCache {
	if opts.Client == nil {
		panic("helios_permissions: RedisCacheOptions.Client is required")
	}
	ttl := opts.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultCacheTTLSeconds
	}
	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = KeyPrefix
	}
	logger := opts.Logger
	if logger == nil {
		logger = SilentLogger()
	}
	return &RedisPermissionCache{
		rdb:       opts.Client,
		ttl:       ttl,
		keyPrefix: prefix,
		logger:    logger,
	}
}

func (c *RedisPermissionCache) key(userID, tenantID string) string {
	return c.keyPrefix + userID + ":" + tenantID
}

func (c *RedisPermissionCache) tenantPattern(tenantID string) string {
	return c.keyPrefix + "*:" + tenantID
}

// Get returns the cached perms or nil on miss. Failures log + return nil.
func (c *RedisPermissionCache) Get(userID, tenantID string) ([]Permission, error) {
	raw, err := c.rdb.Get(context.Background(), c.key(userID, tenantID)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		c.logger.Warn("RedisPermissionCache.Get failed, returning nil (caller falls through to Helios)",
			"err", err, "userId", userID, "tenantId", tenantID)
		return nil, nil
	}
	var perms []Permission
	if err := json.Unmarshal([]byte(raw), &perms); err != nil {
		c.logger.Warn("RedisPermissionCache.Get: cached value is not a valid array, treating as miss",
			"err", err, "raw", raw)
		return nil, nil
	}
	return perms, nil
}

// Set stores perms with NX semantics — only if not present. The host
// service calls this from the in-flight repopulate path after a Helios
// fetch. NX prevents a slow read from resurrecting a value that was
// invalidated after the read started.
func (c *RedisPermissionCache) Set(userID, tenantID string, perms []Permission) error {
	payload, err := json.Marshal(perms)
	if err != nil {
		return fmt.Errorf("RedisPermissionCache.Set: marshal: %w", err)
	}
	ok, err := c.rdb.SetNX(context.Background(), c.key(userID, tenantID), payload, secondsToDuration(c.ttl)).Result()
	if err != nil {
		c.logger.Warn("RedisPermissionCache.Set failed, continuing without cache",
			"err", err, "userId", userID, "tenantId", tenantID)
		return err
	}
	_ = ok // NX result is informational; the SDK doesn't differentiate
	return nil
}

// WriteThrough overwrites the cached value. No NX — explicit overwrite.
// Helios's own writer (ZIN-4901i) uses the same key shape and pattern.
func (c *RedisPermissionCache) WriteThrough(userID, tenantID string, perms []Permission) error {
	payload, err := json.Marshal(perms)
	if err != nil {
		return fmt.Errorf("RedisPermissionCache.WriteThrough: marshal: %w", err)
	}
	if err := c.rdb.Set(context.Background(), c.key(userID, tenantID), payload, secondsToDuration(c.ttl)).Err(); err != nil {
		c.logger.Warn("RedisPermissionCache.WriteThrough failed, continuing without cache",
			"err", err, "userId", userID, "tenantId", tenantID)
		return err
	}
	return nil
}

// Invalidate drops the (userId, tenantId) entry. Logs and returns the
// error on Redis failure — stale data has no automatic recovery
// except TTL expiry.
func (c *RedisPermissionCache) Invalidate(userID, tenantID string) error {
	deleted, err := c.rdb.Del(context.Background(), c.key(userID, tenantID)).Result()
	if err != nil {
		c.logger.Error("RedisPermissionCache.Invalidate failed — cache may be stale for up to TTL seconds",
			"err", err, "userId", userID, "tenantId", tenantID)
		return err
	}
	c.logger.Info("RedisPermissionCache.Invalidate: deleted (userId, tenantId) entry",
		"userId", userID, "tenantId", tenantID, "deleted", deleted)
	return nil
}

// InvalidateTenant drops every entry for a tenant via SCAN.
func (c *RedisPermissionCache) InvalidateTenant(tenantID string) error {
	pattern := c.tenantPattern(tenantID)
	ctx := context.Background()
	var cursor uint64
	totalDeleted := int64(0)
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, pattern, scanBatchSize).Result()
		if err != nil {
			c.logger.Error("RedisPermissionCache.InvalidateTenant failed — cache may be stale for up to TTL seconds",
				"err", err, "tenantId", tenantID)
			return err
		}
		if len(keys) > 0 {
			n, err := c.rdb.Del(ctx, keys...).Result()
			if err != nil {
				c.logger.Error("RedisPermissionCache.InvalidateTenant: DEL failed",
					"err", err, "tenantId", tenantID, "keys", keys)
				return err
			}
			totalDeleted += n
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	c.logger.Info("RedisPermissionCache.InvalidateTenant: deleted all entries for tenant",
		"tenantId", tenantID, "deleted", totalDeleted)
	return nil
}
