# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within Nova-Arsenal, please send an email to **security@nova-arsenal.dev** (or open a private security advisory on GitHub).

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation | 30 days |
| Public disclosure | After fix is released |

## Security Measures

### Container Security

- All containers run with `cap_drop: ALL` and minimal capabilities added back
- `no-new-privileges:true` prevents privilege escalation
- Network isolation between agent and sandbox
- Memory and CPU limits on all services
- Health checks for service monitoring

### Authentication

- JWT tokens with short expiration (15 minutes)
- Refresh tokens for session management
- Password hashing with bcrypt
- Role-based access control (Admin, Analyst, Viewer)

### Tool Governance

- Shell command allow-listing
- Scope enforcement for all tool calls
- Rate limiting to prevent abuse
- Audit logging of all operations
- Secret redaction in logs

### Code Quality

- Automated security scanning (CodeQL, Trivy, TruffleHog)
- Dependency vulnerability auditing
- Pre-commit hooks for secret detection
- Type checking with basedpyright

## Scope

This security policy applies to:

- The `nova-arsenal` Python package
- Docker images published under `informant254/nova-*`
- The web dashboard (`clients/web/`)
- API endpoints

## Out of Scope

- Third-party integrations (LLM providers, etc.)
- Social engineering attacks
- Physical attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x | ✅ Active |
| < 1.0 | ❌ No |

## Best Practices for Users

1. **Use Docker deployment** for isolation
2. **Enable authentication** in production
3. **Keep dependencies updated**
4. **Use strong secrets** for JWT and database
5. **Monitor audit logs** for suspicious activity
6. **Restrict scope** to authorized targets only

## Acknowledgments

We appreciate the security research community and responsible disclosure practices.

Thank you for helping keep Nova-Arsenal secure!
