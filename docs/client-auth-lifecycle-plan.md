# Client Auth Lifecycle Plan

## Goal

Build `@node-in-layers/auth/client` as the single auth lifecycle owner for consumers (frontend SDKs and `mcp-client` adapter usage), while keeping interfaces clean and transport concerns config-driven.

## Core Outcomes

- `client` features expose auth operations other clients use.
- `mcp-client` reads auth from `auth/client` via adapter `getAuth` and does not need to manage direct OAuth2 in this path.
- Auth session state is persistable/hydratable without leaking backend request metadata.
- Token refresh is automatic behind `getAuth()` after login.

## Design Rules

- Keep **session state** separate from **transport config**.
- Do not mix backend feature envelopes with client request contracts.
- Keep login/refresh payloads focused on authentication data.
- Persist only auth session data; never persist request/transport metadata.

## Contracts

### Client features/services surface

- `login`
- `refresh`
- `logout`
- `getState`
- `setState`
- `getAuth` (services; consumed by adapter)

### Persistable auth state

- `token`
- `refreshToken`
- `user` (optional)
- `loginApproach` (optional)
- `tokenExpiresAtMs` (derived)
- `header` / `formatter` (optional adapter shaping)

### Config-driven transport

Use auth API config for client transport behavior:

- `authentication.clientBaseUrl`
- `authentication.clientHeaders`
- `authentication.clientRefreshBufferMs`
- existing `loginPath` / `refreshPath`

## Lifecycle

1. **Login**
   - Caller submits login payload (basic/oidc/apikey style request).
   - Client calls auth API login route and stores returned token/refresh token/user.

2. **Steady state**
   - Callers (including `mcp-client` through adapter) call `getAuth()`.
   - `getAuth()` checks token expiry and uses refresh token automatically when near expiry.

3. **Rehydration**
   - On app reload, caller restores session with `setState(...)`.
   - Subsequent `getAuth()` calls continue lifecycle without forced re-login.

4. **Logout**
   - Clear in-memory state and in-flight refresh state.

## Refresh behavior

- Refresh is available as explicit feature/service call.
- Normal use should not require manual refresh calls.
- Auto-refresh is triggered by `getAuth()` when expiry is within refresh buffer window.
- Concurrent refresh attempts should collapse to one in-flight refresh operation.

## mcp-client integration

- Configure `mcp-client.authAdapter` to resolve `getAuth` from `@node-in-layers/auth/client` services.
- In this mode, `mcp-client` is transport-focused and consumes auth from adapter.
- Shared state requires the same loaded system instance.

## Open follow-up decisions

- Whether to add token-exchange state/caching in `auth/client` for per-target exchanged tokens.
- Whether to add dedicated helper aliases for SDK ergonomics (`hydrateSession`/`exportSession`).
- Whether `getAuth()` should optionally attempt bootstrap login in special machine-to-machine flows (usually no by default).
