# Roadmap

Future enhancements for the Prompt Injection Interceptor.

Contributions welcome — if you're interested in working on any of these, open an issue to discuss.

---

## Planned Enhancements

### 1. Shared Threat Intelligence Feed

**Status:** Concept

A community-maintained blocklist of known malicious URLs, similar to antivirus signature databases or browser safe browsing lists.

**How it would work:**

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ User's PII  │────▶│ Central Service  │────▶│ Blocklist   │
│ (opt-in)    │     │ (review + curate)│     │ (published) │
└─────────────┘     └──────────────────┘     └─────────────┘
       │                                            │
       │         ┌──────────────────────────────────┘
       ▼         ▼
┌─────────────────────┐
│ PII checks URL      │
│ against blocklist   │
│ BEFORE scanning     │
└─────────────────────┘
```

**Components needed:**

1. **Reporting endpoint** — Receives submissions from PII users (opt-in)
2. **Review queue** — Human review to verify submissions, prevent false positives
3. **Blocklist API** — Serves the curated list of known-bad URLs/domains
4. **PII integration** — Fetches blocklist periodically, checks URLs before scanning

**Privacy considerations:**
- Opt-in only — users explicitly enable sharing
- Minimal data — URL + pattern type only, not full page content
- No tracking — no user identification in submissions
- Transparency — published blocklist is public and auditable

**False positive handling:**
- Human review before adding to blocklist
- Appeal process for site owners
- Automatic expiry for entries not re-confirmed
- Severity levels (block vs warn)

---

### 2. Additional Detection Patterns

**Status:** Ongoing

Community contributions of new detection patterns as attack techniques evolve.

**Wanted patterns:**
- Multi-language injections (non-English attack phrases)
- New model token formats as LLMs evolve
- Emerging jailbreak techniques
- Encoding-based attacks (base64, rot13, etc.)

**How to contribute:**
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding patterns.

---

### 3. IDE Integration

**Status:** Concept

Visual indicators in VS Code / JetBrains when browsing to flagged URLs.

- Warning icon in status bar when PII blocks content
- Click to see what was detected
- Quick actions: report false positive, view audit log

---

### 4. Analytics Dashboard

**Status:** Concept

For enterprise deployments, a dashboard showing:

- Blocked attempts over time
- Most common attack patterns
- URLs frequently flagged
- Detection pattern effectiveness

Could integrate with existing SIEM tools via syslog export.

---

### 5. Additional CLI Support

**Status:** Planned

Support for other AI coding assistants as they add hook systems:

- GitHub Copilot CLI (when hooks available)
- Cursor (when hooks available)
- Others as they emerge

---

## Contributing to the Roadmap

Have an idea? Open an issue with the `enhancement` label describing:

1. What problem it solves
2. How it might work
3. Any security considerations

We especially welcome contributions that improve detection without increasing false positives.
