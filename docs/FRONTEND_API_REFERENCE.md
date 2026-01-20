# SPOQ API Frontend Reference

Technical documentation for frontend integration with SPOQ Web APIs.

**Base URL:** `https://api.spoq.dev`

---

## Table of Contents

1. [Authentication Flow](#authentication-flow)
2. [VPS Provisioning Flow](#vps-provisioning-flow)
3. [Endpoint Reference](#endpoint-reference)
4. [State Machines](#state-machines)
5. [Error Handling](#error-handling)
6. [Polling Strategies](#polling-strategies)

---

## Authentication Flow

SPOQ uses a device authorization flow (similar to GitHub CLI / Netflix TV login). The CLI initiates auth, and users approve via browser.

### Flow Diagram

```
┌─────────────┐                      ┌─────────────┐                      ┌─────────────┐
│    CLI      │                      │   Backend   │                      │   Browser   │
└──────┬──────┘                      └──────┬──────┘                      └──────┬──────┘
       │                                    │                                    │
       │ 1. POST /auth/device               │                                    │
       │    { hostname }                    │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │                                    │
       │ 2. { device_code,                  │                                    │
       │      verification_uri,             │                                    │
       │      expires_in, interval }        │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
       │ 3. Display URL to user             │                                    │
       │    User opens in browser ─────────────────────────────────────────────► │
       │                                    │                                    │
       │                                    │ 4. GET /auth/verify?d={base64}     │
       │                                    │ ◄─────────────────────────────────  │
       │                                    │                                    │
       │                                    │ 5. Redirect to GitHub OAuth        │
       │                                    │ ─────────────────────────────────► │
       │                                    │                                    │
       │                                    │ 6. GitHub callback with code       │
       │                                    │ ◄─────────────────────────────────  │
       │                                    │                                    │
       │                                    │ 7. Show approve/deny form          │
       │                                    │ ─────────────────────────────────► │
       │                                    │                                    │
       │                                    │ 8. POST /auth/authorize            │
       │                                    │    { word_code, approved }         │
       │                                    │ ◄─────────────────────────────────  │
       │                                    │                                    │
       │ 9. Poll POST /auth/device/token    │                                    │
       │    { device_code, grant_type }     │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │                                    │
       │ 10. { access_token,                │                                    │
       │       refresh_token }              │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
```

### Step-by-Step

1. **CLI initiates device flow** - `POST /auth/device`
2. **CLI displays verification URL** - User opens in browser
3. **Browser redirects to GitHub OAuth** - User logs in with GitHub
4. **User approves device** - Clicks approve button
5. **CLI receives tokens** - Polling returns access + refresh tokens

---

## VPS Provisioning Flow

### Flow Diagram

```
┌─────────────┐                      ┌─────────────┐                      ┌─────────────┐
│  Frontend   │                      │   Backend   │                      │  Hostinger  │
└──────┬──────┘                      └──────┬──────┘                      └──────┬──────┘
       │                                    │                                    │
       │ 1. GET /api/vps/plans              │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │                                    │
       │ 2. { plans: [...] }                │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
       │ 3. GET /api/vps/datacenters        │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │                                    │
       │ 4. { data_centers: [...] }         │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
       │ 5. POST /api/vps/provision         │                                    │
       │    { ssh_password, plan_id,        │                                    │
       │      data_center_id }              │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │ 6. Create VPS order                │
       │                                    │ ─────────────────────────────────► │
       │                                    │                                    │
       │ 7. 202 Accepted                    │                                    │
       │    { id, hostname,                 │                                    │
       │      status: "provisioning" }      │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
       │ 8. Poll GET /api/vps/status        │                                    │
       │ ─────────────────────────────────► │                                    │
       │                                    │ 9. Check VPS state                 │
       │                                    │ ─────────────────────────────────► │
       │                                    │                                    │
       │ 10. { status: "ready",             │                                    │
       │       ip_address: "..." }          │                                    │
       │ ◄───────────────────────────────── │                                    │
       │                                    │                                    │
```

### Provisioning States

| Status | Description | Next States |
|--------|-------------|-------------|
| `pending` | Initial state, order placed | `provisioning`, `failed` |
| `provisioning` | VPS being created on Hostinger | `ready`, `failed` |
| `ready` | Fully operational | `stopped` |
| `stopped` | VPS powered off | `ready`, `terminated` |
| `failed` | Provisioning failed | (terminal) |
| `terminated` | VPS deleted | (terminal) |

---

## Endpoint Reference

### Authentication Endpoints

#### `POST /auth/device`

Initiates device authorization flow.

**Request:**
```json
{
  "hostname": "my-macbook-pro"
}
```

**Response (200 OK):**
```json
{
  "device_code": "a1b2c3d4e5f6...64chars",
  "verification_uri": "https://api.spoq.dev/auth/verify?d=base64data",
  "expires_in": 300,
  "interval": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `device_code` | string | 64-char hex code for polling |
| `verification_uri` | string | URL for user to visit in browser |
| `expires_in` | number | Seconds until expiration (300 = 5 min) |
| `interval` | number | Minimum seconds between poll requests |

---

#### `POST /auth/device/token`

CLI polls this endpoint to check if user has approved.

**Request:**
```json
{
  "device_code": "a1b2c3d4e5f6...64chars",
  "grant_type": "device_code"
}
```

**Response (Pending - 200 OK):**
```json
{
  "error": "authorization_pending"
}
```

**Response (Approved - 200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "spoq_abc123...",
  "token_type": "Bearer"
}
```

**Response (Denied - 200 OK):**
```json
{
  "error": "access_denied"
}
```

**Response (Expired - 200 OK):**
```json
{
  "error": "expired_token"
}
```

| Error Value | Meaning | Frontend Action |
|-------------|---------|-----------------|
| `authorization_pending` | User hasn't acted yet | Continue polling |
| `access_denied` | User denied authorization | Stop polling, show error |
| `expired_token` | Device code expired | Start new flow |

---

#### `POST /auth/refresh`

Exchange refresh token for new access token.

**Request:**
```json
{
  "refresh_token": "spoq_abc123..."
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "Invalid refresh token"
}
```

---

#### `POST /auth/revoke`

Revoke a refresh token (logout).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "refresh_token": "spoq_abc123..."
}
```

**Response (200 OK):**
```json
{
  "message": "Token revoked successfully"
}
```

---

### VPS Endpoints

#### `GET /api/vps/plans`

List available VPS plans. **No authentication required.**

**Response (200 OK):**
```json
{
  "plans": [
    {
      "id": "hostingercom-vps-kvm1-usd-1m",
      "name": "KVM 1",
      "vcpu": 1,
      "ram_gb": 4,
      "disk_gb": 50,
      "bandwidth_tb": 4,
      "monthly_price_cents": 1399,
      "first_month_price_cents": 499
    },
    {
      "id": "hostingercom-vps-kvm2-usd-1m",
      "name": "KVM 2",
      "vcpu": 2,
      "ram_gb": 8,
      "disk_gb": 100,
      "bandwidth_tb": 8,
      "monthly_price_cents": 1799,
      "first_month_price_cents": 699
    }
  ]
}
```

---

#### `GET /api/vps/datacenters`

List available data centers. **No authentication required.**

**Response (200 OK):**
```json
{
  "data_centers": [
    {
      "id": 9,
      "name": "Phoenix",
      "city": "Phoenix",
      "country": "USA",
      "continent": "North America"
    },
    {
      "id": 12,
      "name": "Amsterdam",
      "city": "Amsterdam",
      "country": "Netherlands",
      "continent": "Europe"
    }
  ]
}
```

---

#### `POST /api/vps/provision`

Provision a new VPS. **Requires authentication.**

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request:**
```json
{
  "ssh_password": "mySecurePassword123",
  "plan_id": "hostingercom-vps-kvm1-usd-1m",
  "data_center_id": 9
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `ssh_password` | string | Yes | Minimum 12 characters |
| `plan_id` | string | No | Defaults to `hostingercom-vps-kvm1-usd-1m` |
| `data_center_id` | number | No | Defaults to `9` (Phoenix, USA) |

**Response (202 Accepted):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "username.spoq.dev",
  "status": "provisioning",
  "message": "VPS provisioning started. Check status for updates."
}
```

**Response (400 Bad Request):**
```json
{
  "error": "SSH password must be at least 12 characters"
}
```

**Response (409 Conflict):**
```json
{
  "error": "User already has an active VPS"
}
```

---

#### `GET /api/vps/status`

Get current VPS status. **Requires authentication.**

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK - Provisioning):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "username.spoq.dev",
  "status": "provisioning",
  "ip_address": null,
  "ssh_username": "spoq",
  "provider": "hostinger",
  "plan_id": "hostingercom-vps-kvm1-usd-1m",
  "data_center_id": 9,
  "created_at": "2026-01-15T10:00:00Z",
  "ready_at": null
}
```

**Response (200 OK - Ready):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "username.spoq.dev",
  "status": "ready",
  "ip_address": "89.116.49.69",
  "ssh_username": "spoq",
  "provider": "hostinger",
  "plan_id": "hostingercom-vps-kvm1-usd-1m",
  "data_center_id": 9,
  "created_at": "2026-01-15T10:00:00Z",
  "ready_at": "2026-01-15T10:08:32Z"
}
```

**Response (404 Not Found):**
```json
{
  "error": "No VPS found for user"
}
```

---

#### `POST /api/vps/start`

Start a stopped VPS. **Requires authentication.**

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "VPS start initiated"
}
```

---

#### `POST /api/vps/stop`

Stop a running VPS. **Requires authentication.**

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "VPS stop initiated"
}
```

---

#### `POST /api/vps/restart`

Restart VPS. **Requires authentication.**

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "VPS restart initiated"
}
```

---

#### `POST /api/vps/reset-password`

Reset VPS root password. **Safe operation - no data loss.**

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request:**
```json
{
  "new_password": "newSecurePassword123"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `new_password` | string | Yes | Minimum 12 characters |

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successful. You can now SSH with the new password."
}
```

---

### Health Check

#### `GET /health`

Health check endpoint.

**Response (200 OK):**
```
OK
```

---

## State Machines

### VPS Provisioning State Machine

```
                    ┌─────────────────────────────────────────────────────────┐
                    │              POST /api/vps/provision                    │
                    │  { ssh_password, plan_id?, data_center_id? }            │
                    └─────────────────────────┬───────────────────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │     PENDING     │
                                    │ (order placed)  │
                                    └────────┬────────┘
                                             │
                          ┌──────────────────┴──────────────────┐
                          │                                     │
                          ▼                                     ▼
                ┌─────────────────┐                   ┌─────────────────┐
                │  PROVISIONING   │                   │     FAILED      │
                │ (VPS creating)  │                   │ (order failed)  │
                └────────┬────────┘                   └─────────────────┘
                         │
                         │ Hostinger creates VPS
                         │ Post-install script runs
                         │
                         ▼
                ┌─────────────────┐
                │      READY      │
                │ (operational)   │
                └────────┬────────┘
                         │
           ┌─────────────┴─────────────┐
           │                           │
           ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│     STOPPED     │◄───────►│      READY      │
│ (powered off)   │ start/  │                 │
└────────┬────────┘  stop   └─────────────────┘
         │
         ▼
┌─────────────────┐
│   TERMINATED    │
│   (deleted)     │
└─────────────────┘
```

### Device Authorization State Machine

```
┌─────────────────────────────────────────────┐
│         POST /auth/device                   │
│    { hostname: "my-device" }                │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
            ┌─────────────────┐
            │     PENDING     │  ← Poll returns: { "error": "authorization_pending" }
            │ (awaiting user) │
            └────────┬────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
    ▼                ▼                ▼
┌────────┐    ┌───────────┐    ┌───────────┐
│APPROVED│    │  DENIED   │    │  EXPIRED  │
│        │    │           │    │ (5 min)   │
└───┬────┘    └─────┬─────┘    └─────┬─────┘
    │               │                │
    ▼               ▼                ▼
{ access_token,   { "error":      { "error":
  refresh_token }   "access_       "expired_
                    denied" }       token" }
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | When |
|------|---------|------|
| `200 OK` | Success | Request completed successfully |
| `202 Accepted` | Async Started | VPS provisioning queued |
| `400 Bad Request` | Invalid Input | Missing/invalid parameters |
| `401 Unauthorized` | Auth Failed | Missing/invalid/expired token |
| `403 Forbidden` | Access Denied | User cannot access resource |
| `404 Not Found` | Not Found | Resource doesn't exist |
| `409 Conflict` | Conflict | User already has active VPS |
| `500 Internal Server Error` | Server Error | Unexpected server error |
| `502 Bad Gateway` | External API Error | GitHub/Hostinger API failed |

### Error Response Format

All errors return JSON with this structure:

```json
{
  "error": "Human-readable error message"
}
```

### Common Errors

| Endpoint | Error | Cause |
|----------|-------|-------|
| `POST /api/vps/provision` | `SSH password must be at least 12 characters` | Password too short |
| `POST /api/vps/provision` | `User already has an active VPS` | One VPS per user limit |
| `GET /api/vps/status` | `No VPS found for user` | User hasn't provisioned |
| `POST /auth/refresh` | `Invalid refresh token` | Token revoked/expired |
| Any authenticated | `Missing authorization header` | No Bearer token |
| Any authenticated | `Invalid token format` | Malformed token |

---

## Polling Strategies

### Device Authorization Polling

```typescript
async function pollForToken(deviceCode: string): Promise<TokenResponse> {
  const POLL_INTERVAL = 5000; // 5 seconds (from API response)
  const MAX_ATTEMPTS = 60;    // 5 minutes total

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const response = await fetch('/auth/device/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_code: deviceCode,
        grant_type: 'device_code'
      })
    });

    const data = await response.json();

    if (data.access_token) {
      return data; // Success!
    }

    if (data.error === 'authorization_pending') {
      await sleep(POLL_INTERVAL);
      continue;
    }

    if (data.error === 'access_denied') {
      throw new Error('User denied authorization');
    }

    if (data.error === 'expired_token') {
      throw new Error('Device code expired');
    }
  }

  throw new Error('Polling timeout');
}
```

### VPS Status Polling

```typescript
async function pollVpsStatus(accessToken: string): Promise<VpsStatus> {
  const POLL_INTERVAL = 3000;  // 3 seconds
  const MAX_ATTEMPTS = 200;    // ~10 minutes total

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const response = await fetch('/api/vps/status', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch status');
    }

    const data = await response.json();

    if (data.status === 'ready') {
      return data; // VPS is ready!
    }

    if (data.status === 'failed') {
      throw new Error('VPS provisioning failed');
    }

    // Still provisioning, continue polling
    await sleep(POLL_INTERVAL);
  }

  throw new Error('Provisioning timeout');
}
```

### Token Refresh Strategy

```typescript
async function makeAuthenticatedRequest(url: string, options: RequestInit) {
  let accessToken = getStoredAccessToken();

  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    }
  });

  if (response.status === 401) {
    // Token expired, try refresh
    const refreshToken = getStoredRefreshToken();
    const refreshResponse = await fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken })
    });

    if (refreshResponse.ok) {
      const { access_token } = await refreshResponse.json();
      storeAccessToken(access_token);

      // Retry original request with new token
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${access_token}`
        }
      });
    }

    // Refresh failed, user needs to re-authenticate
    throw new Error('Session expired');
  }

  return response;
}
```

---

## Token Lifetimes

| Token | Lifetime | Storage |
|-------|----------|---------|
| Access Token (JWT) | 15 minutes | Memory / secure storage |
| Refresh Token | 90 days | Secure persistent storage |
| Device Code | 5 minutes | Temporary (during auth flow) |

---

## Complete Example: Provision Flow

```typescript
// 1. Fetch available plans (no auth required)
const plansResponse = await fetch('/api/vps/plans');
const { plans } = await plansResponse.json();

// 2. Fetch data centers (no auth required)
const dcResponse = await fetch('/api/vps/datacenters');
const { data_centers } = await dcResponse.json();

// 3. User selects plan and data center, enters password
const selectedPlan = plans[0].id;
const selectedDc = data_centers[0].id;
const sshPassword = 'userEnteredPassword123';

// 4. Start provisioning (requires auth)
const provisionResponse = await fetch('/api/vps/provision', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    ssh_password: sshPassword,
    plan_id: selectedPlan,
    data_center_id: selectedDc
  })
});

if (provisionResponse.status === 409) {
  alert('You already have an active VPS');
  return;
}

if (provisionResponse.status === 400) {
  const { error } = await provisionResponse.json();
  alert(error); // e.g., "SSH password must be at least 12 characters"
  return;
}

const { id, hostname, status } = await provisionResponse.json();
console.log(`Provisioning started: ${hostname}`);

// 5. Poll for ready status
const vps = await pollVpsStatus(accessToken);
console.log(`VPS ready at ${vps.ip_address}`);
console.log(`SSH: ssh ${vps.ssh_username}@${vps.ip_address}`);
```

---

## SSH Connection Info

Once a VPS is `ready`, users can connect via SSH:

```bash
ssh spoq@<ip_address>
# Password: the ssh_password provided during provisioning
```

The VPS will have:
- **Hostname**: `{username}.spoq.dev`
- **SSH User**: `spoq`
- **OS**: Ubuntu 22.04 LTS
- **Services**: Conductor (AI orchestration), Caddy (reverse proxy)
