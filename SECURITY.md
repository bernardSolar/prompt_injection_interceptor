# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the Prompt Injection Interceptor, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email the maintainer directly (or use GitHub's private vulnerability reporting)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Considerations for Contributors

### What We Watch For

All pull requests are reviewed for attempts to weaken security:

| Red Flag | Why It's Suspicious |
|----------|---------------------|
| Removing detection patterns | Could allow attacks to pass through |
| Lowering score thresholds | Makes it easier to bypass detection |
| Changing exit codes | Exit 2 = block; changing this breaks protection |
| Disabling audit logging | Hides evidence of attacks |
| Modifying tests to pass | Could mask broken functionality |
| Adding "exceptions" or "allowlists" | Could create bypass mechanisms |

### Protected Files

These files are security-critical and require maintainer approval:

- `prompt-injection-interceptor/src/injection_detector.py` — detection logic
- `prompt-injection-interceptor/hooks/*.py` — all hook scripts
- `scripts/*.sh` — installation scripts run with elevated privileges
- `.github/workflows/*.yml` — CI/CD configuration

### Automated Checks

Our CI pipeline verifies:

1. **All tests pass** — ensures detection still works
2. **No secrets in code** — scans for API keys, tokens
3. **Critical patterns present** — ensures key detections haven't been removed

### Safe Contribution Patterns

✅ **Good contributions:**
- Adding NEW detection patterns (with tests)
- Improving documentation
- Adding more tests
- Fixing bugs that don't weaken detection
- Performance improvements that don't affect security

❌ **Suspicious contributions:**
- Removing or modifying existing patterns without clear justification
- Changing threshold values
- Adding "special cases" that bypass detection
- Modifying how exit codes work
- Changes to audit logging

## For Enterprise Users

If you deploy PII in an enterprise environment:

1. **Use managed settings** with `allowManagedHooksOnly: true`
2. **Monitor audit logs** at `/var/log/prompt-injection-interceptor/`
3. **Pin to specific releases** rather than tracking `main`
4. **Review updates** before deploying new versions

## Acknowledgments

We appreciate responsible security researchers who help make PII better. Contributors who report valid vulnerabilities will be acknowledged (with permission) in our release notes.
