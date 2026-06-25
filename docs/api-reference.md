# API Reference

Nova-Arsenal exposes a REST API for managing agents, findings, and scope.

## Base URL

```
http://localhost:8080/api
```

## Authentication

All endpoints require JWT authentication via Bearer token:

```
Authorization: Bearer <token>
```

## Endpoints

### Health

#### `GET /api/health`

Basic health check.

**Response:**
```json
{
  "status": "healthy",
  "service": "nova-arsenal"
}
```

#### `GET /api/health/detailed`

Detailed health check with component status.

**Response:**
```json
{
  "status": "healthy",
  "service": "nova-arsenal",
  "components": {
    "llm_providers": {
      "ollama/deepseek-r1": true,
      "openai/gpt-4o": false
    }
  }
}
```

### Authentication

#### `POST /api/auth/register`

Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "username": "user",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "user",
  "role": "analyst",
  "is_active": true,
  "created_at": "2026-01-01T00:00:00"
}
```

#### `POST /api/auth/login`

Login and get JWT tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

#### `GET /api/auth/me`

Get current user profile.

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "user",
  "role": "analyst",
  "is_active": true,
  "created_at": "2026-01-01T00:00:00"
}
```

### Agents

#### `GET /api/agents`

List all agents for the current user.

**Response:**
```json
{
  "agents": [
    {
      "id": 1,
      "name": "Agent-example.com",
      "target": "example.com",
      "status": "running",
      "created_at": "2026-01-01T00:00:00"
    }
  ]
}
```

#### `GET /api/agents/{id}`

Get agent details.

**Response:**
```json
{
  "id": 1,
  "name": "Agent-example.com",
  "target": "example.com",
  "objective": "Find all critical vulnerabilities",
  "status": "running",
  "max_steps": 40,
  "current_step": 15,
  "created_at": "2026-01-01T00:00:00",
  "started_at": "2026-01-01T00:01:00",
  "completed_at": null
}
```

#### `POST /api/agents`

Create a new agent.

**Query Parameters:**
- `target` (required): Target to scan
- `objective` (optional): Agent objective

**Response:**
```json
{
  "id": 1,
  "name": "Agent-example.com",
  "target": "example.com",
  "status": "idle"
}
```

#### `DELETE /api/agents/{id}`

Delete an agent (admin only).

**Response:**
```json
{
  "message": "Agent deleted"
}
```

### Findings

#### `GET /api/findings`

List findings with optional filters.

**Query Parameters:**
- `agent_id` (optional): Filter by agent
- `severity` (optional): Filter by severity

**Response:**
```json
{
  "findings": [
    {
      "id": 1,
      "title": "SQL Injection in /api/search",
      "severity": "critical",
      "endpoint": "/api/search",
      "verified": true,
      "created_at": "2026-01-01T00:00:00"
    }
  ]
}
```

#### `GET /api/findings/{id}`

Get finding details.

**Response:**
```json
{
  "id": 1,
  "title": "SQL Injection in /api/search",
  "severity": "critical",
  "description": "Unparameterized query allows...",
  "evidence": "Payload: ' OR 1=1 --",
  "endpoint": "/api/search",
  "cwe_id": "CWE-89",
  "cvss_score": 9.8,
  "verified": true,
  "remediation": "Use parameterized queries",
  "created_at": "2026-01-01T00:00:00",
  "verified_at": "2026-01-01T01:00:00"
}
```

#### `POST /api/findings/{id}/verify`

Mark a finding as verified.

**Response:**
```json
{
  "message": "Finding verified"
}
```

### Scope

#### `GET /api/scope`

List all scope entries.

**Response:**
```json
{
  "scope": [
    {
      "id": 1,
      "target": "example.com",
      "description": "Primary target",
      "is_wildcard": false,
      "created_at": "2026-01-01T00:00:00"
    }
  ]
}
```

#### `POST /api/scope`

Add a target to scope.

**Query Parameters:**
- `target` (required): Target domain/IP
- `description` (optional): Description

**Response:**
```json
{
  "id": 1,
  "target": "example.com",
  "is_wildcard": false
}
```

#### `DELETE /api/scope/{id}`

Remove a target from scope.

**Response:**
```json
{
  "message": "Target removed from scope"
}
```

## WebSocket

### `ws://localhost:8080/ws/agent/{agent_id}`

Real-time agent updates.

**Query Parameters:**
- `user_id`: User ID for connection tracking

**Events:**

| Event | Description |
|-------|-------------|
| `agent_started` | Agent began execution |
| `agent_completed` | Agent finished |
| `agent_error` | Agent encountered error |
| `tool_called` | Tool invocation |
| `tool_result` | Tool output received |
| `finding_discovered` | New finding identified |
| `progress_update` | Progress percentage |
| `log_message` | Agent log output |

**Example Message:**
```json
{
  "type": "tool_called",
  "agent_id": 1,
  "data": {
    "tool": "nmap",
    "args": {"target": "example.com"}
  }
}
```

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message"
}
```

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Server Error |
