# ADR-0005: Web UI Framework

## Status

Accepted

## Context

Nova-Arsenal needs a web dashboard for:
- Agent monitoring and management
- Finding visualization
- User administration
- Real-time updates

Requirements:
- Modern, responsive UI
- Real-time updates via WebSocket
- Server-side rendering for SEO
- Type safety

## Decision

We will use **Next.js 14** with the App Router for the web dashboard.

### Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript |
| Styling | Tailwind CSS |
| State | React hooks + SWR |
| Real-time | WebSocket |
| Auth | NextAuth.js |

### Key Features

1. **App Router**: File-based routing with layouts
2. **Server Components**: Reduced client-side JavaScript
3. **Streaming**: Progressive page loading
4. **API Routes**: Built-in API handling

## Consequences

### Positive

- Modern React patterns
- Excellent developer experience
- Strong TypeScript support
- Built-in optimizations

### Negative

- Node.js runtime required
- More complex than static sites
- Build time for large applications

## Implementation

See `clients/web/` for implementation details.
