# Secure Config Check

A Python-based, read-only security auditing tool for Ubuntu 24.04 LTS. It evaluates 15 selected CIS-aligned controls for the Level 1 Server profile and reports each result as `PASS`, `FAIL`, `ERROR`, or `NOT_APPLICABLE` without changing system settings.

> This project is CIS-aligned with the CIS Ubuntu Linux 24.04 LTS Benchmark, but it is not CIS-certified, is not a full CIS assessment, and is not endorsed or certified by the Center for Internet Security.

## Development Status

Core development is complete.

The project is designed for read-only auditing of supported Ubuntu 24.04 systems, with sanitized output that avoids exposing usernames, password hashes, raw shadow records, and other sensitive values.

## Project Objectives

- Automate 15 selected checks aligned with the CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0, Level 1 Server profile.
- Identify secure, noncompliant, and unavailable configurations.
- Produce readable console and JSON reports.
- Protect sensitive system data and account information.
- Handle missing files, commands, and permission errors safely.
- Support repeatable testing and future security-audit improvements.

## Key Features

- Runs 15 read-only Ubuntu security configuration checks.
- Covers file permissions, SSH, password policies, firewall settings, and account configuration.
- Reports each control as `PASS`, `FAIL`, `ERROR`, or `NOT_APPLICABLE`.
- Produces readable console output and timestamped JSON reports.
- Continues auditing when one category encounters an error.
- Uses sanitized summaries that avoid exposing usernames, password hashes, or raw configuration records.
- Blocks execution on unsupported operating systems.
- Includes 144 automated tests covering normal, insecure, malformed, missing, and denied inputs.

## Supported Environment and Prerequisites

Before running Secure Config Check, confirm that you have:

- Ubuntu Server 24.04 LTS
- Python 3.12 or later
- Git
- Python virtual environment support
- Permission to audit the target system
- Administrator access for checks that read protected files such as `/etc/shadow`
- UFW and OpenSSH installed if you want those controls fully evaluated

For development and testing, install:

- `pytest`
- Visual Studio Code or another Python editor

> Run this tool only on systems you own or are authorized to assess. The tool performs read-only checks and does not automatically change system settings.

## Installation and Setup

Run these commands in Ubuntu 24.04:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git ufw openssh-server

git clone https://github.com/kelvinburt-ux/Cyb333-Security-automation-.git
cd Cyb333-Security-automation-/secure-config-check

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install pytest
```

## How to Run the Automated Tests

The automated tests can run on Windows or Ubuntu. The actual security audit only runs on Ubuntu 24.04 LTS.

```bash
python -m pytest -q
```

## How to Run the Security Audit

Display the help menu:

```bash
python -m secure_config_check.cli --help
```

Run the audit on a supported Ubuntu 24.04 host:

```bash
python -m secure_config_check.cli
```

## How to Generate the JSON Report

```bash
python -m secure_config_check.cli --json-output reports/ubuntu-audit.json
```

This writes the project metadata, benchmark information, summary totals, and all 15 ordered control results to the selected JSON file.

## List of All 15 Controls

The project uses a fixed 15-control registry in the current code. The catalog below matches the IDs, categories, and titles defined in the implementation.

| # | Control ID | Category | Title |
| --- | --- | --- | --- |
| 1 | 7.1.1 | File permissions | Access to passwd database |
| 2 | 7.1.3 | File permissions | Access to group database |
| 3 | 7.1.5 | File permissions | Access to shadow database |
| 4 | 5.1.16 | SSH | SSH MaxAuthTries |
| 5 | 5.1.19 | SSH | SSH PermitEmptyPasswords |
| 6 | 5.1.20 | SSH | SSH PermitRootLogin |
| 7 | 5.3.3.2.2 | Password policy | Minimum password length |
| 8 | 5.4.1.1 | Password policy | Password expiration |
| 9 | 5.4.1.3 | Password policy | Password expiration warning |
| 10 | 4.1.1 | Firewall | UFW is installed |
| 11 | 4.1.2 | Firewall | UFW service is configured |
| 12 | 4.1.3 | Firewall | UFW incoming default policy |
| 13 | 5.4.2.1 | Account configuration | Root is the only UID 0 account |
| 14 | 7.2.1 | Account configuration | Accounts use shadowed passwords |
| 15 | 7.2.2 | Account configuration | Shadow password fields are not empty |

## Project Architecture and Repository Structure

The project is intentionally small and easy to follow:

- `secure_config_check/cli.py` handles command-line parsing, environment detection, and the main audit flow.
- `secure_config_check/auditor.py` runs each category once, validates that exactly 15 control results are returned, and keeps them in the fixed order used by the report output.
- `secure_config_check/checks/` contains one module per category: `permissions.py`, `ssh.py`, `passwords.py`, `firewall.py`, and `accounts.py`.
- `secure_config_check/models.py` defines the `CheckResult` and `AuditReport` data structures used throughout the project.
- `secure_config_check/reporting.py` formats sanitized console output and writes the JSON report payload.
- `tests/` contains the regression and behavior tests that exercise CLI behavior, reporting, edge cases, and safe sanitization.

If you are new to the codebase, start with the CLI entry point, then follow the audit flow into each category module and the reporting layer.

## Ubuntu Audit Results

The project’s live Ubuntu audit record shows the following results for the 15 included controls:

| Status | Count |
| --- | ---: |
| PASS | 8 |
| FAIL | 2 |
| ERROR | 5 |
| NOT_APPLICABLE | 0 |
| Total | 15 |

This summary reflects the project’s documented Ubuntu assessment and is the report used for the final audit evidence.

## Explanation of FAIL versus ERROR

- `FAIL` means a control was checked and the current setting does not meet the expected requirement.
- `ERROR` means the check could not be completed safely because the needed file, command, service, or permission state was unavailable or uncertain.
- `PASS` means the control meets the expected requirement.
- `NOT_APPLICABLE` means the control does not apply in the current environment.

The project’s CLI explicitly treats `ERROR` as higher priority than `FAIL` when returning the process exit code.

## Screenshots and Project Evidence

The project documentation can include screenshot evidence in the following locations:

![Console report placeholder](docs/screenshots/termsnap- Full%20test%20suite.png)

![JSON output placeholder](docs/screenshots/termsnap%20-%2016-cli-commit.png)

![Audit summary placeholder](docs/screenshots/termsnap%20-%20all%2015%20control%20funtions%20built%20and%20tested.png)

## Safety, Privacy, and Limitations

- The tool is read-only. It does not modify configuration files or remediation settings.
- The tool is designed to run only on Ubuntu Linux 24.04 LTS and blocks other platforms.
- The project intentionally sanitizes results before writing them to the console or JSON output.
- Output does not include usernames, hostnames, password hashes, raw shadow records, credentials, or other sensitive values.
- This project checks a selected set of CIS-aligned controls, not every CIS recommendation for Ubuntu.
- The project is not a full CIS assessment and is not CIS-certified.
- The project does not perform remote scanning or automatic remediation.
- The output is dependent on local permissions and the availability of the relevant system files and services.

## Future Improvements

- Expand the control set beyond the current 15 selected checks.
- Add additional benchmark and profile support for other Ubuntu or Linux distributions.
- Improve reporting options with HTML, CSV, and richer filtering for audit outcomes.
- Add optional integration with CI pipelines and repeatable lab workflows.
- Extend documentation with more example reports and troubleshooting notes.

## AI-Assisted Development Disclosure

This project was developed with AI-assisted coding support during the implementation and documentation process. The final technical content, command usage, and project scope were verified against the current repository code and tests before being retained in the documentation.

## License or Academic-Use Note

This repository is intended for academic study, security learning, and demonstration of a read-only Linux configuration audit workflow. It is not a commercial product, a formal CIS certification artifact, or a production security assessment tool.
