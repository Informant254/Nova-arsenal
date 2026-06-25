# ADR-0004: Authentication Approach

## Status

Accepted

## Context

Nova-Arsenal requires authentication for:
- Multi-user support
- API access control
- Role-based permissions

Requirements:
- Stateless authentication for API
- Support for web UI sessions
- Role-based access control

## Decision

We will implement **JWT-based authentication** with:

1. **Access Tokens**: Short-lived (15 minutes)
2. **Refresh Tokens**: Long-lived (7 days)
3. **Password Hashing**: bcrypt
4. **Role-Based Access**: Admin, Analyst, Viewer

### Token Structure

```json
{
  "sub": 1,
  "email": "user@example.com",
  "role": "analyst",
  "exp": "2026-01-01T00:15:00Z",
  "type": "access"
}
```

### Roles

| Role | Permissions |
|------|-------------|
| Admin | Full access, user management |
| Analyst | Create agents, verify findings |
| Viewer | Read-only access |

## Consequences

### Positive

- Stateless, scalable authentication
- Standard JWT ecosystem
- Easy integration with web frameworks
- Clear permission model

### Negative

- Token refresh complexity
- Secret management required
- No server-side session revocation

## Implementation

See `nova_arsenal/auth/` for implementation details.
