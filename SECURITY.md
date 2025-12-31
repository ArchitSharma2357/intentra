# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in intentra, please report it responsibly:

1. **Do not open a public GitHub issue**
2. **Email security details to the maintainers** (contact information in repository)
3. **Allow 30 days for patch development and coordinated disclosure**
4. **Coordinate public announcement** after patch is available

## Responsible Disclosure Timeline

- **Day 0:** Security issue reported
- **Day 1-3:** Initial assessment and reproduction
- **Day 3-25:** Patch development and testing
- **Day 25-30:** Patch release and coordinated disclosure
- **Day 30+:** Public announcement (embargoed until patch available)

## Scope of Vulnerability Reports

We accept reports for:
- Cryptographic implementation flaws
- DoS protection bypass mechanisms
- State machine correctness issues
- Memory safety issues (in intentra code)
- Rate limiting bypass
- Replay protection bypass

We do not accept reports for:
- Vulnerabilities in dependencies (report to upstream)
- Configuration errors by users
- Operational deployment issues
- Missing features (request as feature instead)

## Security Testing

intentra has been tested with:
- 200+ adversarial test cases
- Logical peer simulation to 1,000,000 concurrent peers
- Real UDP network testing to 20,480 concurrent peers
- Memory bounds verification
- Cryptographic edge case testing

## Known Limitations

See [README.md](./README.md) for threat model documentation.

The following are **out of scope** for intentra:
- Volumetric DDoS protection (use firewall)
- Network-layer attacks (use ISP filtering)
- Application-layer attacks (use input validation)
- Key compromise recovery (use key rotation)

## Attribution

Security researchers who report valid vulnerabilities will be:
- Contacted individually
- Thanked in the security advisory
- Given 30 days advance notice before public disclosure
