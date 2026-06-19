# helios-permissions-go

Go SDK for cross-service authorization in the Wazobia Tech platform.
Cache-first `callerHasPermission` / `getUserPermissions` / `explain` /
`invalidate` / `writeThrough` surface, mirroring the TypeScript and
Python SDKs.

## What it does

A single process-local `Client` answers "is user U allowed perm P in
tenant T?" with:

1. **Cache hit** — returns the cached perm array (Redis GET, sub-ms).
2. **Cache miss** — calls Helios's `GET /internal/permissions/:userId?tenantId=<uuid>`,
   which is HMAC-signed with `SIGNATURE_SHARED_SECRET`. Populates the
   cache with the new perms.
3. **Helios unreachable + `staleOnError=true` (default)** — returns
   the cached value (fail-closed: allow stale, deny fresh).
4. **Helios unreachable + `staleOnError=false`** — returns the error.

`writeThrough` / `invalidate` / `invalidateTenant` are the write path
that Helios itself calls after every role-changing mutation. See
[helios's `permission-cache.service.ts](../helios/src/internal/permission-cache.service.ts)
(ZIN-4901i).

## Installation

```bash
go get github.com/wazobiatech/helios-permissions-go
```

Module path: `github.com/wazobiatech/helios-permissions-go`. Go 1.24+.

## Quick start

```go
package main

import (
    "context"
    "log"
    "os"

    hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

func main() {
    r, err := hp.Create(hp.CreateOptions{
        HeliosBaseURL:         os.Getenv("HELIOS_BASE_URL"),
        SignatureSharedSecret: os.Getenv("SIGNATURE_SHARED_SECRET"),
        RedisURL:              os.Getenv("PERMISSION_REDIS_URL"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer r.Close()

    allowed, err := r.Client.CallerHasPermission(
        context.Background(),
        "user-123",
        "tenant-abc",
        hp.PermissionAthensProjectView,
    )
    if err != nil {
        log.Fatal(err)
    }
    if !allowed {
        log.Println("denied")
    }
}
```

## Configuration

| Env var | Purpose | Required |
|---|---|---|
| `HELIOS_BASE_URL` | Helios service base URL (e.g. `https://helios.svc`) | yes |
| `SIGNATURE_SHARED_SECRET` | HMAC shared secret for Helios auth | yes |
| `PERMISSION_REDIS_URL` | Redis URL for the shared permission cache | yes |
| `HELIOS_SOURCE_SERVICE` | `x-source-service` header (default `helios-permissions-go`) | no |
| `CACHE_TTL_SECONDS` | Cache TTL (default `60`) | no |
| `HELIOS_FETCH_TIMEOUT_MS` | Per-fetch timeout to Helios (default `2000`) | no |
| `STALE_ON_ERROR` | `1`/`true` = allow stale on Helios error; default `1` | no |

`PERMISSION_REDIS_URL` is **the same Redis Helios writes to**. Sharing
the instance is the point: Helios's `writeThrough` keeps every
service's cache fresh after a role change. This is the key invariant
that makes the cross-language SDKs correct.

## Public surface

```go
type Client interface {
    CallerHasPermission(ctx context.Context, userID, tenantID string, perm Permission) (bool, error)
    GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error)
    Explain(ctx context.Context, userID, tenantID string, perm Permission) (*Explanation, error)
    Invalidate(ctx context.Context, userID, tenantID string) error
    InvalidateTenant(ctx context.Context, tenantID string) error
    WriteThrough(ctx context.Context, userID, tenantID string, perms []Permission) error
}

type Result struct {
    Client Client
    Redis  *redis.Client
    Helios *HeliosClient
    Close  func() error
}

func Create(opts CreateOptions) (*Result, error)
```

`Permission` and `Role` are typed (see `role_permissions.go`) — typos
fail at compile time.

## HMAC contract

The SDK signs requests the same way the TS / Python SDKs do, and
the same way Helios's internal `hmac.ts` verifier expects:

```
payload  = METHOD + path + timestamp      // METHOD is "GET" (uppercase)
digest   = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
headers  = x-source-service, x-signature, x-timestamp
reject   if |now - timestamp| > 300s
```

The path is signed **without** the query string. This matches Helios's
deviation from the canonical nexus-mcp contract — see the package
comment in `client.go`. When Helios's verifier is fixed to canonical,
this client updates in lockstep with the TS / Python SDKs.

## Cache key shape

```
helios:perms:{userId}:{tenantId}    →    JSON array of permission strings
```

The key shape is the cross-language contract — must match Helios's
`permission-cache.service.ts` and the TS / Python / Laravel SDKs.
Drift here would silently break every consumer.

## Architecture

- `cache.go` — `PermissionCache` interface (Get, Set, WriteThrough, Invalidate, InvalidateTenant).
- `in_memory_cache.go` — process-local impl with `sync.RWMutex`. For tests + single-instance dev.
- `redis_cache.go` — Redis impl (`go-redis/v9`). The production choice.
- `client.go` — `HeliosClient`, the HMAC-signed `GET /internal/permissions/:userId` transport.
- `permission_client.go` — the cache-first `Client` facade. Includes in-flight coalescing.
- `factory.go` — `Create(opts)`, the only public constructor. Owns Redis lifecycle.
- `role_permissions.go` — **generated** from `permission-contract/permissions.json`. Do not edit by hand.

## Tests

```bash
go test -race ./...
```

40+ tests across:
- `role_permissions_test.go` — role × perm table; transfer-is-OWNER-only invariant; universal perm invariant.
- `client_test.go` — HMAC signing; 404 → `not_a_member`; non-2xx / network error → `HeliosUnreachableError`; context cancellation.
- `permission_client_test.go` — cache hit, miss + Helios OK, miss + Helios error + `staleOnError` true/false, in-flight coalescing, writeThrough.
- `in_memory_cache_test.go` — `Get`/`Set`/`WriteThrough`/`Invalidate`/`InvalidateTenant`; defensive copy; concurrent readers.
- `redis_cache_test.go` — same shape against `miniredis`; key shape pinned against the cross-language contract; TTL expiry; corrupt-value-as-miss.
- `factory_test.go` — required-options validation, injected-Redis lifecycle, factory-owned-Redis lifecycle, fail-fast on unreachable Redis.

## Codegen

The `role_permissions.go` file is generated from the
[permission-contract](https://github.com/wazobiatech/permission-contract)
JSON. Two ways to regenerate:

```bash
# 1. The Go-native emitter (no Node required — useful in slim Go images):
go run ./cmd/codegen <path-to-permissions.json> > helios_permissions/role_permissions.go

# 2. The Node emitter (source of truth, used by the contract repo's CI):
node ../permission-contract/scripts/codegen-go.mjs ../permission-contract/permissions.json > helios_permissions/role_permissions.go
```

The CI pipeline fetches `permissions.json` from the public GitHub
mirror at a pinned version, runs the Go emitter, and diffs against
the committed file. Drift fails the build.

## Versioning

Semver. The Go module proxy auto-ingests tagged commits. To publish
a new version:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Related

- TypeScript: [`@wazobiatech/helios-permissions`](../helios-permissions)
- Python: [`wazobiatech-helios-permissions`](../helios-permissions-py)
- Laravel: [`wazobia/helios-permissions`](../helios-permissions-laravel) (planned — ZIN-4901h)
- Contract: [`wazobiatech/permission-contract`](../permission-contract)
