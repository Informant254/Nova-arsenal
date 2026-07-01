# Building a Nova Skill

Nova's skills system lets anyone add a new platform connector (or other
modular capability) without touching her core agent loop. This is the
easiest way to contribute to Nova Arsenal.

## Quick Start — Build a Platform Connector

1. Create a folder under `skills/` named after your connector:
   ```
   skills/bugcrowd-connector/
   ```

2. Add `skill.json`:
   ```json
   {
     "name": "bugcrowd-connector",
     "version": "1.0.0",
     "author": "your-github-handle",
     "description": "Pulls public programs from Bugcrowd",
     "type": "platform_connector",
     "entry": "connector.py",
     "entry_class": "BugcrowdConnector",
     "requires_credentials": ["api_token"],
     "python_requires": ["httpx>=0.27"],
     "tags": ["bug-bounty", "bugcrowd"],
     "nova_min_version": "1.0.0"
   }
   ```

3. Add `connector.py` implementing `PlatformConnector`:
   ```python
   from platform_connector import PlatformConnector, PlatformKind, Target

   class BugcrowdConnector(PlatformConnector):
       platform_name = "bugcrowd"
       platform_kind = PlatformKind.BUG_BOUNTY

       def list_targets(self, limit=50) -> list[Target]:
           ...  # call Bugcrowd's API, return Target objects

       def get_target_detail(self, target_id: str) -> Target:
           ...
   ```

4. Test it locally:
   ```bash
   python3 -c "
   from skill_manifest import SkillRegistry
   r = SkillRegistry(skills_dir='skills')
   r.discover()
   loaded = r.load('bugcrowd-connector', {'api_token': 'YOUR_TOKEN'})
   print(loaded.instance.list_targets(limit=5))
   "
   ```

5. Open a PR. Skills are reviewed for:
   - No hardcoded secrets
   - No automated finding submission without explicit human-review boundary
     (see `hackerone-connector/connector.py` for the pattern — Nova drafts,
     a human submits)
   - Honest scope_summary / asset_types — don't overstate what a target covers

## Skill Types

| Type | Purpose |
|------|---------|
| `platform_connector` | Bug bounty / CTF / lab platforms (HackerOne, Bugcrowd, HTB, THM) |
| `tool` | A new security tool wrapper Nova can call |
| `reporting` | Custom report output formats |
| `analysis` | New correlation/scoring logic |

## Why Connectors Don't Auto-Submit Findings

Every connector in this repo deliberately raises `NotImplementedError` on
`submit_finding()` unless the platform is a CTF flag-submission style
(HackTheBox `own` endpoint, which has no real-world disclosure
consequence). For bug bounty platforms, Nova drafts a finding — a human
reviews and submits it themselves. This is a permanent design boundary,
not a TODO. Please keep new connectors consistent with this.

## The Target Model

Every connector returns `Target` objects so Nova's reasoning layer
(`TargetReasoner` in `platform_connector.py`) can compare opportunities
across completely different platforms on equal footing — a HackerOne
program and a HackTheBox machine both reduce to the same shape:

```python
Target(
    id, platform, kind, name, url,
    scope_summary, tags, difficulty,
    max_reward_usd, asset_types, raw
)
```

Fill in `asset_types` accurately (`web`, `api`, `network`, `smb`,
`mobile`, `cloud`, `active_directory`) — this is what lets
`TargetReasoner` match targets against Nova's actual module strengths
instead of guessing.
