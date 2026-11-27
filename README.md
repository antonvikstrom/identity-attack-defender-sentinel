# Identity Attack in Defender XDR & Sentinel

![Validate detection rules](https://github.com/antonvikstrom/identity-attack-defender-sentinel/actions/workflows/validate-rules.yml/badge.svg)

One identity attack followed end to end in the Microsoft security stack: **detect, triage, respond, report**.
Detections are written as code, tested against sample data, and checked in CI on every push.

## Status

| Part | Status |
|---|---|
| Detection rules (KQL), written as YAML with spec | ✅ 5 rules |
| Hunting queries | ✅ 2 queries |
| Sample-data tests for every rule and hunt | ✅ |
| Schema check in CI (GitHub Actions) | ✅ |
| Live run in a Microsoft 365 E5 + Sentinel trial tenant | ⏳ January 2027 |
| Validation table from live data, incident report, playbook | ⏳ after the live run |

## The scenario

A password spray against test accounts, followed by a successful sign-in from an unusual country.
The "attacker" then tries to keep access: adds a privileged role, sets up mail forwarding to an
outside address, and registers a new MFA method. Everything runs in my own isolated trial tenant,
against test accounts only.

## Detections

| ID | Detects | Table | ATT&CK | Severity |
|---|---|---|---|---|
| P6-001 | Password spray followed by a successful sign-in | SigninLogs | T1110.003, T1078.004 | High |
| P6-002 | Successful sign-in from a country the user hasn't used in 14 days | SigninLogs | T1078.004 | Medium |
| P6-003 | User added to a privileged Entra ID role | AuditLogs | T1098.003 | High |
| P6-004 | Mail forwarding (inbox rule or mailbox) to an external address | OfficeActivity | T1114.003 | Medium |
| P6-005 | MFA method registered from an IP the user has never signed in from | AuditLogs, SigninLogs | T1098.005 | Medium |

## Hunting queries

| ID | Question | Table | ATT&CK |
|---|---|---|---|
| H-001 | Were credentials added to an app, so someone can sign in as the app later? | AuditLogs | T1098.001 |
| H-002 | Did a user sign in from two countries closer in time than travel allows? | SigninLogs | T1078.004 |

## How each detection is built

Every rule is a YAML file in `detections/rules/` with:

- **goal** and **ATT&CK** mapping
- **threshold**, with the reason for it
- **blind spots** and **expected false positives**, written down honestly
- **test**: which attack step should fire it, and the expected result
- **tuning history**: every change after creation, with the reason

Each rule has a test in `detections/tests/`: the same query run against a small `datatable`
of sample events with a planted attack and normal noise. A test passes when the query returns
exactly the planted rows and nothing else. Tests were run in Azure Data Explorer, which uses
the same KQL as Sentinel.

**Example of tuning:** the first version of P6-001 also matched an IP where a successful
sign-in came *before* the failures (for example an app retrying an old password). I added
that case as a test, saw the false positive, and changed the rule to require a success after
the first failure. The change is recorded in the rule's tuning history.

## CI

`tools/check_rules.py` checks every rule file on each push: required fields, allowed status
and severity values, ID and ATT&CK technique formats, dates, and duplicate IDs. It exits with
an error code on any problem, so GitHub Actions marks the run as failed.

Run it locally:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tools/check_rules.py
```

## Repository layout

```
detections/
  rules/        YAML rules (P6-001 … P6-005) and _template.yaml
  tests/        sample-data tests for every rule and hunt (.kql)
  watchlists/   (planned) known VPN IPs and admin accounts for tuning
hunting/        hunting queries with a header: question, ATT&CK, how to read the results
tools/          check_rules.py (schema check)
docs/           (planned) incident report, triage note, design decisions, cost
response/       (planned) playbook with human approval
.github/        CI workflow
```

## Known limits

- The KQL tests run by hand in Azure Data Explorer, not in CI.
- Sample data follows Microsoft's documented table formats; the live run will confirm them.
- Slow password sprays and sprays rotated across many IPs get past P6-001. They need
  separate rules, listed as next steps rather than built, since the lab can't produce
  realistic data for them.