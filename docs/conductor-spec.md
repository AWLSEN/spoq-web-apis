# Conductor - JWT Protection Spec

Conductor already works. Just need to add JWT protection for HTTP and WebSocket connections.

## What's Needed

1. **JWT validation middleware** - for HTTP and WebSocket
2. **install.sh** - packaging/distribution

---

## Central Backend Reference

| Item | Value |
|------|-------|
| Production URL | `https://spoq-api-production.up.railway.app` |
| Device flow init | `POST /auth/device` |
| Device flow token | `POST /auth/device/token` |
| Token refresh | `POST /auth/refresh` |

---

## JWT Protection

### Config

```toml
# /etc/conductor/config.toml

[auth]
# Same secret as central backend (Railway env: JWT_SECRET)
jwt_secret = "your-secret-from-railway"

# UUID of user who owns this VPS
owner_id = "user-uuid-from-provisioning"
```

### Expected JWT Claims

```rust
struct Claims {
    sub: String,        // User ID (UUID) - MUST match owner_id
    exp: usize,         // Expiration timestamp
    iat: usize,         // Issued at
}
```

### Validation Logic

```rust
fn validate_request(req: &Request, config: &Config) -> Result<(), AuthError> {
    // 1. Trust localhost (SSH users already authenticated)
    if req.peer_addr().ip().is_loopback() {
        return Ok(());
    }

    // 2. Extract Bearer token
    let token = req
        .header("Authorization")
        .strip_prefix("Bearer ")
        .ok_or(AuthError::MissingToken)?;

    // 3. Verify JWT signature (HS256)
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;

    // 4. CRITICAL: Verify user owns this VPS
    if claims.sub != config.owner_id {
        return Err(AuthError::Forbidden);  // 403
    }

    Ok(())
}
```

### For WebSocket

Same validation, but token comes from:
- Query param: `ws://host:8080/ws?token=eyJ...`
- Or first message after connect

```rust
fn validate_websocket(req: &WsRequest, config: &Config) -> Result<(), AuthError> {
    // Trust localhost
    if req.peer_addr().ip().is_loopback() {
        return Ok(());
    }

    // Get token from query param
    let token = req.query("token").ok_or(AuthError::MissingToken)?;

    // Same JWT validation
    let claims = decode::<Claims>(...)?;

    if claims.sub != config.owner_id {
        return Err(AuthError::Forbidden);
    }

    Ok(())
}
```

### Auth Errors

| Error | HTTP Code | When |
|-------|-----------|------|
| MissingToken | 401 | No Authorization header / no token param |
| InvalidToken | 401 | Bad signature or malformed |
| TokenExpired | 401 | exp claim passed |
| Forbidden | 403 | token.sub != owner_id |

### Startup Validation

Refuse to start without valid config:

```rust
fn validate_config(config: &Config) -> Result<(), StartupError> {
    if config.jwt_secret.is_empty() || config.jwt_secret.len() < 32 {
        return Err(StartupError::InvalidJwtSecret);
    }
    if config.owner_id.is_empty() {
        return Err(StartupError::MissingOwnerId);
    }
    Ok(())
}
```

---

## Security Summary

| Request From | Auth Required |
|--------------|---------------|
| `localhost` / `127.0.0.1` | No - trusted (SSH user) |
| External IP | Yes - valid JWT with matching owner_id |

| Attack | Protection |
|--------|------------|
| No token | 401 Unauthorized |
| Wrong user's token | 403 Forbidden (owner_id mismatch) |
| Forged token | 401 (signature verification fails) |
| Expired token | 401 (exp check) |
| Stolen binary | Useless without jwt_secret + owner_id config |

---

## Testing

```bash
# Get JWT from central backend
./scripts/test-flow.sh
# Token saved to ~/.spoq/test-credentials.json

ACCESS_TOKEN=$(jq -r '.access_token' ~/.spoq/test-credentials.json)

# Test HTTP endpoint (replace with actual path)
curl http://<VPS_IP>:8080/<YOUR_HTTP_ENDPOINT> \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"your": "payload"}'

# Test WebSocket (replace with actual path)
wscat -c "ws://<VPS_IP>:8080/<YOUR_WS_ENDPOINT>?token=$ACCESS_TOKEN"

# Test localhost trust (SSH into VPS first)
ssh root@<VPS_IP>
curl http://localhost:8080/<YOUR_HTTP_ENDPOINT> -d '{"your": "payload"}'
# Should work WITHOUT token (localhost trusted)
```
