# ADR-0003: Database Choice

## Status

Accepted

## Context

Nova-Arsenal needs to store:
- User accounts
- Agent configurations
- Security findings
- Target scope

Requirements:
- Lightweight for single-user/small team deployments
- Support for async operations (FastAPI)
- Easy setup and maintenance
- SQLite for simplicity

## Decision

We will use **SQLite** as the primary database with **SQLAlchemy 2.0** as the ORM.

### Schema Design

- `users`: User accounts and roles
- `agents`: Agent configurations and status
- `findings`: Discovered vulnerabilities
- `scope`: Target scope definitions

### Justification

1. **Simplicity**: SQLite requires no external services
2. **Portability**: Single file database
3. **Performance**: Sufficient for agent workloads
4. **Async Support**: aiosqlite for async operations

## Consequences

### Positive

- Zero configuration database
- Easy backup (single file)
- No database server required
- Good async support

### Negative

- Limited concurrent writes
- No horizontal scaling
- Limited query optimization

## Future Considerations

For larger deployments, consider:
- PostgreSQL for multi-user scenarios
- Database migration path via Alembic

## Implementation

See `nova_arsenal/db/` for implementation details.
