# Security Policy

Port Overseer is a network auditing and port visibility tool that interacts with local interfaces, loopback services, and LAN discovery mechanisms. Because of its security-adjacent functionality, responsible vulnerability reporting is important.

## Supported Versions

Only the current stable branch is supported for security updates.

| Version | Supported          | Notes                      |
|--------|--------------------|----------------------------|
| main   | :white_check_mark: | Stable branch (active)     |
| older  | :x:                | Not supported              |

> Only the latest stable branch receives security patches. Users should always pull the most recent updates from `main`.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Port Overseer, please report it responsibly. Do not disclose issues publicly before a fix is available.

### Reporting channels

Please use one of the following:

- GitHub Security Advisories
- Private contact email: `shumwayjohnny@gmail.com`
- If neither is available, submit a private/confidential issue if supported by the platform

---

### What counts as a security issue

Relevant vulnerabilities include:

- Unauthorized access to scan results or internal network data
- Command injection or unsafe parsing of CLI input
- Bypassing scan filters, restrictions, or intended scope controls
- Exposure of LAN devices, ports, or services outside user intent
- Manipulation of scan output in a way that could mislead analysis
- Any behavior that could escalate tool behavior beyond intended local use

---

### What to include in your report

To help us respond effectively, please include:

- Clear description of the issue
- Steps to reproduce (commands, inputs, environment)
- Expected vs actual behavior
- Version/commit reference (if applicable)
- Logs, screenshots, or payloads if relevant
- Any assessment of impact (optional but helpful)

---

### Response timeline

- Initial response: 48–72 hours
- Triage update: within 7 days
- Fix timeline:
  - Critical issues: immediate priority patch
  - High severity: next release
  - Medium/low severity: scheduled updates

---

### Disclosure policy

We follow coordinated disclosure:

- Please allow time for a fix before public disclosure
- We may request clarification or collaborate during resolution
- Credit may be given to reporters unless anonymity is requested
- After a fix is released, details may be published for transparency

---

### Security scope

Port Overseer is intended for authorized environments only. Users are responsible for ensuring they have permission to scan networks and interact with discovered services.

The tool does not intentionally access external systems without explicit configuration.

---

Thank you for helping keep Port Overseer secure and reliable. Every report helps strengthen the tool’s trustworthiness and safety.
