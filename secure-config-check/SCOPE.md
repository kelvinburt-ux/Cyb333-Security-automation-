# Project Scope

## Target Environment

- Operating system: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- Environment: Oracle VirtualBox lab VM
- Benchmark: CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0
- Profile: Level 1 - Server

## Project Objective

Build a read-only Python auditing tool that checks 15 Ubuntu security
settings and reports whether each setting passes, fails, produces an
error, or is not applicable.

## Control Categories

- 3 file-permission checks
- 3 SSH checks
- 3 password-policy checks
- 3 firewall checks
- 3 account-configuration checks

## Report Formats

- JSON report
- Readable console report

## Exclusions

- No automatic remediation
- No Level 2 controls
- No workstation-profile controls
- No remote scanning
- No production systems
- No collection of password hashes or credentials
- No claim of CIS certification

## Limitations

This student project evaluates a selected group of CIS-aligned controls.
It does not perform a complete CIS assessment and is not certified or
endorsed by the Center for Internet Security.