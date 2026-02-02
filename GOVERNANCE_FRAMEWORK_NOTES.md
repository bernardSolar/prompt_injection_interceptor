# Governance Framework Notes

Ideas for evolving the hooks framework into a comprehensive AI governance solution.

**Status:** Early thinking / brainstorming

---

## The Core Philosophy

> "The leash doesn't need to be smarter than the dog. It just needs to be attached to something fixed."

An AI coding agent doesn't try to write insecure code. It writes *working* code. It produces a SQL query that returns the right results. It generates a login function that authenticates users. It creates a Dockerfile that builds successfully. The code works. It also happens to be exploitable.

**The fundamental problem:** The AI doesn't know what it doesn't know, and it has no mechanism for finding out.

**The solution:** External verification that works regardless of whether the AI "knows better" on any given day. Not because we don't trust the AI, but because trust is not a substitute for evidence.

Every serious engineering discipline works this way:
- Aircraft don't fly because the designer said they're safe — they fly because independent testing has *failed to find* the ways in which they're unsafe
- Bridges don't stand because the engineer trusts their calculations — they stand because independent review has *failed to find errors* in those calculations

The AI's code is the **conjecture**. The governance layer is the **refutation mechanism**.

---

## The Industry Convergence

Three different companies. Three different AI models. One shared insight: **the agent needs an external check that it cannot override.**

| Platform | Hook Type | Config Location |
|----------|-----------|-----------------|
| Claude Code | `PreToolUse` / `PostToolUse` | `.claude/settings.json` |
| Gemini CLI | `BeforeTool` / `AfterTool` | `.gemini/settings.json` |
| GitHub Copilot | `preToolUse` | `.github/hooks/*.json` |

All three arrived at essentially the same architecture independently. That convergence is evidence the pattern is correct.

**This means governance policies are portable.** The same validation script, the same OPA policy pack, works regardless of which AI your team uses. Write the governance once, apply it everywhere.

The thing that changes fast (the AI model) is decoupled from the thing that should change slowly and deliberately (the security policy).

---

## Bidirectional Governance

The framework works in two directions — protecting the LLM from the world, AND protecting the world from the LLM:

```
                    ┌─────────────────────┐
                    │                     │
   INPUT            │      AI Agent       │           OUTPUT
   GOVERNANCE       │   (Claude/Gemini)   │       GOVERNANCE
                    │                     │
                    └─────────────────────┘
        │                                           │
        ▼                                           ▼
┌───────────────────┐                   ┌───────────────────┐
│ Protect the LLM   │                   │ Protect the world │
│ FROM the world    │                   │ FROM the LLM      │
├───────────────────┤                   ├───────────────────┤
│ • Prompt injection│                   │ • OWASP Top 10    │
│ • Jailbreaks      │                   │ • Security vulns  │
│ • Data exfil      │                   │ • Compliance      │
│ • Malicious URLs  │                   │ • Industry regs   │
│                   │                   │ • Best practices  │
│ Hook: PostToolUse │                   │ Hook: PreToolUse  │
│ (WebFetch etc.)   │                   │ (Write/Edit/Bash) │
└───────────────────┘                   └───────────────────┘
        │                                           │
        └─────────────┬─────────────────────────────┘
                      ▼
              ┌───────────────┐
              │ Same engine:  │
              │ • OPA/Rego    │
              │ • PASS/FAIL/  │
              │   HALT        │
              │ • Tier 1/2/3  │
              │ • Audit logs  │
              └───────────────┘
```

### Input Governance (Protect the LLM)

Validates content *coming into* the AI's context:

| Hook | Tool | What It Catches |
|------|------|-----------------|
| `PostToolUse` | WebFetch, WebSearch | Prompt injection, malicious instructions |
| `PostToolUse` | Read | Poisoned files, embedded attacks |
| `UserPromptSubmit` | (user input) | Jailbreak attempts, bypass requests |

**Example:** The Prompt Injection Interceptor (PII) — already built!

### Output Governance (Protect the World)

Validates content *produced by* the AI before it takes effect:

| Hook | Tool | What It Catches |
|------|------|-----------------|
| `PreToolUse` | Write, Edit | SQL injection, hardcoded secrets, weak crypto |
| `PreToolUse` | Bash | Dangerous commands, data exfiltration |
| `PreToolUse` | Commit | Policy violations before they're committed |

**Examples:**
- OWASP Top 10 violations
- Industry compliance (HIPAA, PCI-DSS, SOX)
- Code quality standards

### One Framework, Multiple Governors

The same architecture supports pluggable policy packs:

| Governor | Direction | Purpose |
|----------|-----------|---------|
| `pii-governor` | Input | Prompt injection protection |
| `owasp-governor` | Output | Security best practices |
| `hipaa-governor` | Output | Healthcare compliance |
| `pci-governor` | Output | Payment card industry |
| `finreg-governor` | Output | Financial services |
| `quality-governor` | Output | Code standards, test coverage |

All sharing:
- Same hook infrastructure
- Same PASS/FAIL/HALT model
- Same OPA/Rego engine
- Same audit logging
- Same GaaS backend (optional)

### The Product Vision

**For developers:** One-command install of governance packs relevant to their industry.

```bash
/plugin install owasp-governor
/plugin install hipaa-governor
```

**For enterprises:** Centralised policy management across all AI coding agents, all developers, all projects.

**For regulated industries:** Auditable evidence that AI-generated code was validated against compliance requirements before reaching production.

---

## 1. OPA/Rego Policy Engine

Use Open Policy Agent (OPA) and Rego language for encoding governance rules.

**Benefits:**
- Declarative, auditable policy definitions
- Industry standard for policy-as-code
- Separates policy from enforcement logic
- Version controlled, testable policies

**Example Rego policy:**
```rego
package ai.governance

default allow = false

# Block writes to sensitive directories
deny[msg] {
    input.tool == "Write"
    startswith(input.file_path, "/etc/")
    msg := "Cannot write to system directories"
}

# A05: SQL injection via string interpolation
deny[msg] {
    input.tool == "Write"
    contains(input.content, "f\"SELECT")
    msg := "SQL injection risk: use parameterised queries, not f-strings"
}

# A02: Weak cryptography
deny[msg] {
    input.tool == "Write"
    regex.match("hashlib\\.(md5|sha1)", input.content)
    msg := "Weak hash algorithm: use SHA-256 or stronger"
}

# A05: Debug mode in production
deny[msg] {
    input.tool == "Write"
    regex.match("DEBUG\\s*=\\s*True", input.content)
    msg := "Debug mode enabled: this exposes internals to attackers"
}
```

---

## 2. Three-State Decisions: PASS / FAIL / HALT

Extend hook exit codes beyond binary PASS/FAIL:

| Exit Code | Decision | Meaning | Epistemology |
|-----------|----------|---------|--------------|
| 0 | **PASS** | Definitely safe | Verified conjecture |
| 2 | **FAIL** | Definitely unsafe | Refuted conjecture |
| 3 | **HALT** | Cannot determine | Honest uncertainty |

**HALT is the key innovation.** It's the system saying: *I know that I don't know.*

Rather than guessing on ambiguous cases, the system stops and asks a human. This is epistemic honesty — acknowledging that some questions can't be answered by pattern matching.

**Use cases for HALT:**
- Ambiguous situations requiring human judgement
- High-risk operations that need explicit approval
- Policy violations that might have legitimate exceptions
- Learning mode: "Would you allow this?"

**Example flow:**
```
AI writes code
    │
    ▼
Governance evaluates
    │
    ├── PASS (exit 0) ──▶ Code proceeds automatically
    │
    ├── FAIL (exit 2) ──▶ Code blocked, AI sees reason, can fix and retry
    │
    └── HALT (exit 3) ──▶ Human reviews, decides PASS or FAIL
```

---

## 3. Rule Tiers (Based on Encodability)

Not all security rules are equally encodable. Being transparent about this is the value proposition.

### Tier 1 — Deterministic (Machine Decides)

Pattern matching catches known anti-patterns with high confidence and low false positives.

- Source document unambiguous
- No human input required
- Output: PASS or FAIL

**Examples:**
```python
# These are always wrong — no context needed
query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
hashlib.md5(password)                                  # Weak crypto
DEBUG = True                                           # Debug in prod
eval(user_input)                                       # Code injection
pickle.loads(untrusted_data)                          # Deserialisation
```

### Tier 2 — Context Required (Machine Flags, Human Decides)

Pattern matching detects *potential* issues, but context matters.

- Source document is ambiguous
- Output: HALT (await human decision)

**Examples:**
- "Is this file write necessary?"
- "Does this API call comply with data policy?"
- Missing authentication on a route (maybe it's intentionally public?)
- No rate limiting (maybe it's an internal service?)

### Tier 3 — Design Level (Cannot Encode Automatically)

Cannot be fully automated — but heuristics can flag potential issues for human review.

- Architectural decisions
- Business logic validation
- Trust boundaries
- "Should a user be able to approve their own expense claim?"

- Output: **HALT** (always requires human decision)

**The honest acknowledgement:**
> A governance system that claims to catch everything is less trustworthy than one that is transparent about its boundaries.

---

## 4. What Pattern Matching Can and Cannot Do

### ✅ CAN Detect

**Known anti-patterns:**
- MD5 for password hashing
- Debug mode in production configs
- Hardcoded API keys
- Pickle deserialisation of untrusted data
- SQL via string interpolation

**Absence of defences:**
- No authentication decorator on route handler
- No rate limiting on login endpoint
- No logging in error handler
- Missing CSRF protection

Detecting that something is *missing* is often more reliable than judging whether something *present* is sufficient.

### ❌ CANNOT Detect

**Architecture:**
- Trust boundaries
- Service mesh configuration
- Data flow across microservices

**Business logic:**
- Full stop
- "Can a manager approve their own team's budget?"
- "Should this discount code stack with other promotions?"

---

## 5. Concrete Implementation

### Minimal Validation Script (Bash)

Ten lines that catch three OWASP Top 10 categories:

```bash
#!/bin/bash
# Read what the agent is about to write
CONTENT=$(cat /dev/stdin | jq -r '.content // .tool_input.content // .')

# A03: SQL injection via string interpolation
if echo "$CONTENT" | grep -P 'f".*SELECT.*\{' > /dev/null; then
    echo '{"decision":"block","reason":"SQL injection risk: use parameterised queries"}'
    exit 2
fi

# A02: Broken crypto
if echo "$CONTENT" | grep -P 'hashlib\.(md5|sha1)' > /dev/null; then
    echo '{"decision":"block","reason":"Weak hash algorithm: use SHA-256 or stronger"}'
    exit 2
fi

# A05: Debug mode
if echo "$CONTENT" | grep -P 'DEBUG\s*=\s*True' > /dev/null; then
    echo '{"decision":"block","reason":"Debug mode enabled in production"}'
    exit 2
fi

exit 0
```

### Full Architecture with OPA

```
AI Agent (Claude/Gemini/Copilot)
        │
        ▼
Hook fires (PreToolUse / BeforeTool / preToolUse)
        │
        ▼
Validation script receives JSON
        │
        ▼
Script sends code to OPA governance server
        │
        ▼
OPA evaluates Rego policies (OWASP Top 10, etc.)
        │
        ▼
Returns PASS (exit 0) / FAIL (exit 2) / HALT (exit 3)
        │
        ▼
Agent proceeds, fixes, or waits for human review
```

---

## 6. Policy Document Parser

Build a tool that reads policy documents (like OWASP guides) and classifies rules by tier.

**Input:** URL or document (e.g., https://owasp.org/Top10/2025/A05_2025-Injection/)

**Output:**
```json
{
  "source": "OWASP Top 10 2025 - A05 Injection",
  "rules": [
    {
      "id": "A05-1",
      "description": "Detect SQL injection patterns",
      "tier": 1,
      "encodable": true,
      "suggested_pattern": "f[\"'].*SELECT.*\\{"
    },
    {
      "id": "A05-2",
      "description": "Validate all user inputs",
      "tier": 2,
      "encodable": false,
      "reason": "Requires context about what constitutes 'user input'"
    }
  ]
}
```

**Tier classification heuristics:**
- Contains specific patterns/keywords → Tier 1
- Uses words like "validate", "ensure", "appropriate" → Tier 2
- Discusses architecture, design, process → Tier 3

---

## 7. Governance-as-a-Service (GaaS)

Remote, independent governance verification for AI coding agents.

> "The governance infrastructure is on a completely separate machine that the AI has zero access to. It can't compromise it through prompt injection, context manipulation, or any other means because it's physically elsewhere."

**Architecture:**
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   AI Agent      │────▶│  Thin Client     │────▶│  GaaS Server        │
│   (untrusted)   │     │  Hook            │     │  (trusted)          │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
                              │                          │
                              │    API call              │ - OPA/Rego engine
                              │◀─────────────────────────│ - LLM review
                              │    PASS/FAIL/HALT        │ - Audit logging
                        ┌─────▼─────┐                    │ - Threat intel
                        │ Exit 0/2/3│                    │
                        └───────────┘                    │
                                                         ▼
                                                  ┌─────────────┐
                                                  │ Audit Store │
                                                  │ (immutable) │
                                                  └─────────────┘
```

**The local hook becomes trivial:**
```python
#!/usr/bin/env python3
import requests, sys, json

response = requests.post(
    "https://governance.example.com/validate",
    json=json.load(sys.stdin),
    timeout=5
)

result = response.json()
if result["decision"] == "block":
    print(f"BLOCKED: {result['reason']}")
    sys.exit(2)
if result["decision"] == "halt":
    print(f"NEEDS REVIEW: {result['reason']}")
    sys.exit(3)
sys.exit(0)
```

**Value proposition:**
- AI cannot compromise governance (physically separate)
- Centralised policy management across all developers
- Tamper-proof audit logs
- Compliance reporting built-in
- Cross-organisation threat sharing

**Business model:**
- Free tier: Basic pattern detection, limited API calls
- Pro tier: LLM-enhanced review, custom policies, HALT workflow
- Enterprise: On-prem deployment, SSO, compliance reports, SLA

---

## 8. OWASP-Based Governors

Build governors based on established security standards.

### OWASP Top 10 2025 — Encodability Analysis

Source: https://owasp.org/Top10/2025/

| Category | Tier | Encodable? | Notes |
|----------|------|------------|-------|
| A01 - Broken Access Control | 2 | Partially | Can detect missing decorators |
| A02 - Cryptographic Failures | 1 | Yes | Weak algos are pattern-matchable |
| A03 - Injection | 1 | Yes | SQL, command, XSS patterns |
| A04 - Insecure Design | 3 | No | Fundamental design flaws |
| A05 - Security Misconfiguration | 1-2 | Partially | Debug mode yes, firewall rules no |
| A06 - Vulnerable Components | 1 | Yes | CVE database checks |
| A07 - Auth Failures | 2 | Context needed | Missing auth detectable |
| A08 - Data Integrity Failures | 2 | Context needed | Deserialisation yes |
| A09 - Logging Failures | 1 | Yes | Can check for logging presence |
| A10 - SSRF | 1 | Yes | URL patterns in requests |

### OWASP LLM Top 10 2025

Specific to LLM applications — highly relevant for AI coding agents.

| Category | Tier | Encodable? | Notes |
|----------|------|------------|-------|
| Prompt Injection | 1 | Yes | **PII does this!** |
| Sensitive Info Disclosure | 1-2 | Partially | API keys yes, context no |
| Supply Chain | 1 | Yes | Package vulnerability checks |
| Data Poisoning | 3 | Hard | Training data issues |
| Improper Output Handling | 2 | Context needed | |
| Excessive Agency | 2 | Policy needed | Scope limits |
| System Prompt Leakage | 1 | Yes | Pattern matching |
| Vector/Embedding Issues | 3 | Specialised | |
| Misinformation | 3 | Very hard | |
| Unbounded Consumption | 1 | Yes | Rate limits, token counts |

---

## 9. The Recursive Observation

> "The governance system I've been building — the Rego policies, the validation server, the hook infrastructure — is itself being written with the help of an AI coding assistant. Which means the AI is writing the code that governs the AI. Which means the governance system catches issues in its own construction."

This isn't a paradox. It's exactly how it should work. The leash doesn't need to be smarter than the dog. It just needs to be attached to something fixed.

---

## 10. The Thing Worth Fighting For

> "The most important thing about hooks isn't what they catch today. It's that they establish an architectural principle — external verifiability — that persists regardless of what the AI is doing internally."

As long as AI coding agents have an externally inspectable boundary, we can govern them.

The moment an AI architecture emerges that operates *without* hookable boundaries — autonomous agents that don't pass through a tool-use lifecycle — the governance pattern breaks.

**The thing worth fighting for isn't any particular policy or any particular tool. It's the hookable architecture itself.**

---

## Implementation Priority

1. **HALT exit code** — Quick win, enables human-in-the-loop
2. **OPA/Rego integration** — Industry standard, separates policy from code
3. **OWASP Tier 1 rules** — Immediate security value, high confidence
4. **Tier classification** — Helps prioritise what to automate
5. **GaaS** — Longer term, needs infrastructure
6. **Policy parser** — Research project, LLM-assisted

---

## Questions to Resolve

- [ ] How does HALT interact with different AI agents? (notification mechanism?)
- [ ] Can OPA run efficiently in a hook? (startup time ~10ms acceptable?)
- [ ] What's the API contract for GaaS?
- [ ] How to handle HALT timeout? (auto-fail after N minutes?)
- [ ] Licensing for OWASP-based governors? (OWASP is CC, OPA is Apache 2.0)
- [ ] How to handle the "fourteenth PR of the day" problem? (human fatigue)

---

## The Uncomfortable Question

> "If you're using AI coding assistants — and if you're a developer in 2026, you almost certainly are — here's the uncomfortable question: what sits between the AI's output and your codebase?"

- If the answer is "nothing," you're shipping unreviewed code at machine speed.
- If the answer is "the AI reviews its own code," that's not a refutation mechanism — it's the same conjecture wearing a different hat.
- If the answer is "code review by another human," that's fine as far as it goes, but it doesn't scale to the rate at which AI generates code.

The pieces are all there. OPA is open source. The hooks infrastructure exists in every major AI coding tool. The OWASP frameworks are Creative Commons.

The question is whether you assemble them before or after the AI ships a SQL injection to production.
