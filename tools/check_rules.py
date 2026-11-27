"""Check that every detection rule follows the template.

Usage (from the repo root):  python tools/check_rules.py
Exits with code 1 if any rule has a problem, so the GitHub Action fails.
"""
import re
import sys
from datetime import date
from pathlib import Path

import yaml

RULES_DIR = Path("detections/rules")
TESTS_DIR = Path("detections/tests")

REQUIRED_FIELDS = [
    "id", "title", "status", "severity", "goal", "mitre", "data_sources",
    "schedule", "threshold", "query", "entities", "blind_spots",
    "false_positives", "test", "tuning_history",
]
ALLOWED_STATUS = {"draft", "testing", "production"}
ALLOWED_SEVERITY = {"informational", "low", "medium", "high"}
ALLOWED_ENTITY_TYPES = {"Account", "IP", "Host", "URL", "Mailbox", "CloudApplication"}
ID_PATTERN = re.compile(r"^P6-\d{3}$")                # P6-001
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")  # T1110 or T1110.003


def is_filled(value):
    """True if a text value is not empty or only spaces."""
    return isinstance(value, str) and value.strip() != ""


def check_rule(rule):
    """Return a list of problems in one rule. An empty list means the rule is OK."""
    if not isinstance(rule, dict):
        return ["the file is not a set of key: value pairs"]

    errors = []
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"missing field: {field}")
    if errors:
        return errors  # the checks below need these fields to exist

    if not ID_PATTERN.match(str(rule["id"])):
        errors.append(f"id '{rule['id']}' should look like P6-001")
    if not is_filled(rule["title"]):
        errors.append("title is empty")
    if rule["status"] not in ALLOWED_STATUS:
        errors.append(f"status '{rule['status']}' must be one of {sorted(ALLOWED_STATUS)}")
    if rule["severity"] not in ALLOWED_SEVERITY:
        errors.append(f"severity '{rule['severity']}' must be one of {sorted(ALLOWED_SEVERITY)}")
    if not is_filled(rule["query"]) or rule["query"].strip().startswith("// KQL goes here"):
        errors.append("query is empty")

    mitre = rule["mitre"]
    if not isinstance(mitre, list) or len(mitre) == 0:
        errors.append("mitre must be a list with at least one item")
    else:
        for i, item in enumerate(mitre, start=1):
            if not isinstance(item, dict) or not is_filled(item.get("tactic")):
                errors.append(f"mitre item {i}: tactic is empty")
            technique = item.get("technique") if isinstance(item, dict) else None
            if not TECHNIQUE_PATTERN.match(str(technique)):
                errors.append(f"mitre item {i}: technique '{technique}' should look like T1110.003")

    # New: entity mapping, so Sentinel can build the incident graph.
    entities = rule["entities"]
    if not isinstance(entities, list) or len(entities) == 0:
        errors.append("entities must be a list with at least one item")
    else:
        for i, ent in enumerate(entities, start=1):
            if not isinstance(ent, dict):
                errors.append(f"entities item {i}: must have type and column")
                continue
            if ent.get("type") not in ALLOWED_ENTITY_TYPES:
                errors.append(f"entities item {i}: type '{ent.get('type')}' must be one of {sorted(ALLOWED_ENTITY_TYPES)}")
            column = ent.get("column")
            if not is_filled(column):
                errors.append(f"entities item {i}: column is empty")
            elif isinstance(rule["query"], str) and column not in rule["query"]:
                errors.append(f"entities item {i}: column '{column}' does not appear in the query")

    # New: the test fields must be filled in.
    test = rule["test"]
    if not isinstance(test, dict):
        errors.append("test must have attack_step and expected_result")
    else:
        for key in ("attack_step", "expected_result"):
            if not is_filled(test.get(key)):
                errors.append(f"test.{key} is empty")

    history = rule["tuning_history"]
    if not isinstance(history, list) or len(history) == 0:
        errors.append("tuning_history must be a list with at least one entry")
    else:
        for i, entry in enumerate(history, start=1):
            if not isinstance(entry, dict) or not isinstance(entry.get("date"), date):
                errors.append(f"tuning_history entry {i}: date must look like 2026-10-18")
            if not isinstance(entry, dict) or not is_filled(entry.get("change")):
                errors.append(f"tuning_history entry {i}: change is empty")

    # New: every rule needs its sample-data test file.
    test_file = TESTS_DIR / f"{rule['id']}-test.kql"
    if not test_file.exists():
        errors.append(f"test file missing: {test_file}")

    return errors


def main():
    # Files starting with "_" (like the template) are not real rules.
    rule_files = [p for p in sorted(RULES_DIR.glob("*.yaml")) if not p.name.startswith("_")]
    if not rule_files:
        print("No rules to check yet.")
        return 0

    failed = 0
    seen_ids = {}
    for path in rule_files:
        try:
            with path.open(encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors = [f"invalid YAML: {e}"]
        else:
            errors = check_rule(rule)
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            if rule_id in seen_ids:
                errors.append(f"id {rule_id} is also used in {seen_ids[rule_id]}")
            elif rule_id:
                seen_ids[rule_id] = path.name

        if errors:
            failed += 1
            print(f"FAIL  {path}")
            for e in errors:
                print(f"      - {e}")
        else:
            print(f"OK    {path}")

    print(f"\n{len(rule_files)} rule(s) checked, {failed} with problems.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())