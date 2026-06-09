# Security Policy — Nova Arsenal

> Nova Arsenal is a dual-use security research framework.  
> This page covers responsible disclosure for the tool itself **and** a channel to report observed misuse in the wild.

---

## ⚠️ Reporting Misuse in the Wild

If you have observed Nova Arsenal being used against systems **without authorisation**, please report it immediately.

**What to include:**
- Date and time of observed activity
- Target system or IP range (if known)
- Evidence (logs, screenshots, network captures)
- How you identified Nova as the tool being used

**Report to:** Open a [private security advisory](https://github.com/Informant254/Nova-arsenal/security/advisories/new)  
**Response time:** Within 48 hours

All misuse reports are treated confidentially. You will not be publicly identified without your consent.

---

## 🔒 Reporting Vulnerabilities in Nova Itself

If you find a security vulnerability **in Nova Arsenal's own code** (e.g. a way to bypass the approval workflow, privilege escalation in the tool itself, or a way to weaponise it beyond its intended scope):

1. **Do not open a public issue.**
2. Go to [Security Advisories](https://github.com/Informant254/Nova-arsenal/security/advisories/new) and open a private advisory.
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

**Response SLA:**

| Severity | First Response | Fix Target |
|----------|---------------|------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 5 days | 30 days |
| Low | 10 days | 90 days |

---

## ✅ Authorised Use Policy

Nova Arsenal is licensed for use **only** on systems you own or have **explicit written authorisation** to test.

Authorised use includes:
- Penetration testing your own infrastructure
- CTF competitions and training labs (e.g. HackTheBox, TryHackMe, OWASP Juice Shop)
- Authorised bug bounty programmes with a defined scope
- Security research in isolated lab environments

Unauthorised use includes:
- Scanning or attacking systems without written permission
- Using Nova against cloud infrastructure you do not own
- Incorporating Nova into malware, botnets, or attack platforms
- Removing or bypassing the approval workflow

Violations may constitute criminal offences under the CFAA (US), Computer Misuse Act (UK), and equivalent laws globally.

---

## 🚫 Out of Scope

The following are **not** covered by this policy:
- Intentional vulnerabilities in the bundled OWASP Juice Shop (those are by design — see [Juice Shop's own policy](https://github.com/juice-shop/juice-shop/security/policy))
- Social engineering attempts against the maintainer
- Physical security issues
- Issues in third-party tools Nova calls (nmap, sqlmap, etc.) — report those upstream

---

## 🤝 Safe Harbour

If you discover and responsibly disclose a genuine vulnerability or misuse incident through this channel, the maintainer will:
- Not pursue legal action against you for the act of discovery
- Acknowledge your contribution (with your permission)
- Work with you to understand and fix the issue

This safe harbour **does not apply** to active exploitation or attacks.

---

## 📬 Contact

| Channel | Address |
|---------|---------|
| Private advisory (preferred) | [GitHub Security Advisories](https://github.com/Informant254/Nova-arsenal/security/advisories/new) |
| General security questions | Open a [Discussion](https://github.com/Informant254/Nova-arsenal/discussions) |

---

*Nova Arsenal v4.2 · Last updated: June 2026*
