# HANDOFF — helios-permissions-go

Status snapshot for the Go SDK mirror of `@wazobiatech/helios-permissions`.

## TL;DR

Go SDK shipped. Mirrors the TS / Python SDKs' cache-first
`callerHasPermission` surface. Codegen is wired against
`wazobiatech/permission-contract@v1.0.0` and the CI pipeline fails
on drift. Tag `v0.1.0` to publish.

## What's in v0.1.0

- `Client` interface: `CallerHasPermission`, `GetUserPermissions`, `Explain`, `Invalidate`, `InvalidateTenant`, `WriteThrough`.
- `Create(opts) (*Result, error)` factory that wires `HeliosClient` + `RedisPermissionCache` + `Client`. Owns Redis lifecycle when given a URL; respects injected lifecycle.
- `InMemoryPermissionCache` for tests and single-instance dev.
- `RedisPermissionCache` (`go-redis/v9`): key shape `helios:perms:{userId}:{tenantId}`, 60s TTL, NX on `Set`, overwrite on `WriteThrough`, SCAN-based `InvalidateTenant`.
- HMAC signing matches the TS / Python SDKs and Helios's `hmac.ts` verifier: `METHOD + path + timestamp` (path WITHOUT query string).
- In-flight coalescing for concurrent Helios fetches on the same key.
- `cmd/codegen/main.go` Go-native emitter (alternative to the Node emitter in `permission-contract`).
- 6 test files; `go test -race ./...` is green.
- Codegen fixture in `permission-contract/tests/fixtures/` matches the in-repo `role_permissions.go` byte-for-byte (modulo header).

## Why this lives in its own repo

- Different module path (`github.com/wazobiatech/helios-permissions-go`).
- Different release cadence (Go services have different needs than the TS / Python services).
- The Go module proxy auto-ingests tagged commits — no separate publish step.
- Pinning the contract version per-SDK (via the codegen fixture test) is easier when each SDK has its own `role_permissions.go` checked in.

## Critical files

| File | Purpose |
|---|---|
| `helios_permissions/role_permissions.go` | GENERATED from `permission-contract/permissions.json`. The closed `Permission` and `Role` types live here. |
| `helios_permissions/cache.go` | `PermissionCache` interface. |
| `helios_permissions/redis_cache.go` | Production cache impl. Key shape pinned here. |
| `helios_permissions/in_memory_cache.go` | Process-local impl. |
| `helios_permissions/client.go` | `HeliosClient` (HMAC transport). |
| `helios_permissions/permission_client.go` | Cache-first `Client` facade. |
| `helios_permissions/factory.go` | `Create` factory. |
| `cmd/codegen/main.go` | Go-native emitter. |
| `helios_permissions_test/*` | 6 test files; `go test -race ./...` is green. |
| `bitbucket-pipelines.yml` | vet → test → codegen-diff. Tag v* → publish. |

## Dependencies

| Module | Version | Why |
|---|---|---|
| `github.com/redis/go-redis/v9` | `v9.7.0` | The Redis client `gsc-mcp` uses. Cross-service consistency. |
| `github.com/alicebob/miniredis/v2` | `v2.38.0` | Test dep. In-process Redis simulator. |

Stdlib only for everything else (`crypto/hmac`, `crypto/sha256`,
`encoding/hex`, `net/http`, `context`, `sync`, `time`).

## Architecture decisions

- **HMAC deviation.** `METHOD + path + timestamp` (path WITHOUT query string) — same as the TS / Python SDKs. Helios's internal `hmac.ts` verifier signs the same way. When Helios's verifier is fixed to canonical, this client updates in lockstep.
- **Cache key shape.** `helios:perms:{userId}:{tenantId}`. The cross-language contract — must match Helios's writer and the TS / Python / Laravel SDKs. Drift here would silently break every consumer.
- **Cache TTL = 60s.** Safety net for invalidation failures. Matches the TS / Python SDKs.
- **`StaleOnError=true` by default.** Fail-closed: allow stale on Helios error so a brief Helios outage doesn't lock everyone out. Matches the TS / Python SDKs.
- **In-flight coalescing.** 10 concurrent `CallerHasPermission` calls for the same `(user, tenant)` result in ≤2 upstream fetches (1 if all start before the cache write).
- **Factory-owned Redis lifecycle.** `Create` closes the Redis client it built (when given a URL) and leaves injected clients alone.

## How to publish

```bash
git tag v0.1.0
git push origin v0.1.0
```

The Go module proxy auto-ingests tagged commits. No separate publish step.

## How to consume

```go
import (
    hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

r, err := hp.Create(hp.CreateOptions{
    HeliosBaseURL:         os.Getenv("HELIOS_BASE_URL"),
    SignatureSharedSecret: os.Getenv("SIGNATURE_SHARED_SECRET"),
    RedisURL:              os.Getenv("PERMISSION_REDIS_URL"),
})
if err != nil { log.Fatal(err) }
defer r.Close()

allowed, err := r.Client.CallerHasPermission(ctx, "user-123", "tenant-abc", hp.PermissionAthensProjectView)
```

## Known issues

- **`resolvePermissions` returns the underlying slice without copying.** This is a known minor issue (callers shouldn't mutate, but a defensive copy is cheap). Tracked separately; not blocking v0.1.0.
- **No event-driven invalidator.** Per the plan, v1 of the Go / Laravel SDKs relies on the 60s TTL + Helios's `writeThrough`. A follow-up ticket can add a Kafka consumer if a Go service needs real-time event-driven invalidation.

## Future work

- Add a `Clock` interface for deterministic time-travel in tests (currently uses `time.Now`).
- Add Prometheus / OpenTelemetry instrumentation on the cache miss → Helios fetch path.
- Investigate a `predis`-style `httpsnoop`-style middleware for the Helios client (e.g. for retries with backoff).

## Verification

Local:

```bash
go vet ./...
go test -race ./...
go run ./cmd/codegen ../permission-contract/permissions.json > helios_permissions/role_permissions.go
git diff --exit-code helios_permissions/role_permissions.go
```

CI runs all three steps on every push; tag-driven `v*` builds also
re-run them.
