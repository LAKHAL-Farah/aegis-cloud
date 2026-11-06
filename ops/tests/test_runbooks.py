"""Alarms and runbooks cannot drift apart: every runbook an alarm names exists and has the four parts."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOKS = ROOT / "docs" / "runbooks"
PARTS = ("## Symptom", "## Check", "## Fix", "## Verify")


def named_by_alarms() -> set[str]:
    main = (ROOT / "terraform/modules/monitoring/main.tf").read_text()
    names = set(re.findall(r"\$\{var\.runbook_dir\}/([a-z-]+)\.md", main))
    names.discard("")
    if "${each.key}-down.md" in main:                       # pipeline alarms: one runbook per component
        sec = (ROOT / "terraform/live/security/ops.tf").read_text()
        comps = re.search(r"pipeline_components\s*=\s*\[([^\]]*)\]", sec).group(1)
        names |= {f"{c}-down" for c in re.findall(r'"([a-z]+)"', comps)}
    return names


def test_every_alarm_names_a_runbook_that_exists():
    names = named_by_alarms()
    assert {"cis-alarm", "detector-down", "responder-down"} <= names
    missing = [n for n in names if not (RUNBOOKS / f"{n}.md").exists()]
    assert not missing, f"alarms point at runbooks that do not exist: {missing}"


def test_every_runbook_has_the_four_parts_and_is_indexed():
    index = (RUNBOOKS / "README.md").read_text()
    for path in sorted(RUNBOOKS.glob("*.md")):
        if path.name == "README.md":
            continue
        text = path.read_text()
        assert all(part in text for part in PARTS), f"{path.name} is missing one of {PARTS}"
        assert path.name in index, f"{path.name} is not in the runbook index"


def test_the_commands_runbooks_tell_you_to_run_exist_in_the_makefiles():
    targets = set(re.findall(r"^([a-z0-9-]+):", (ROOT / "ops/ops.mk").read_text(), re.M))
    targets |= set(re.findall(r"^([a-z0-9-]+):", (ROOT / "Makefile").read_text(), re.M))
    for path in RUNBOOKS.glob("*.md"):
        for t in re.findall(r"`make ([a-z0-9-]+)", path.read_text()):
            assert t in targets, f"{path.name}: `make {t}` is not a target"
