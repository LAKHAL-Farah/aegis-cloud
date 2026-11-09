"""The documents are part of the product, so they are tested: paths exist, numbers match the evidence, make targets are real."""
import glob
import json
import re
from pathlib import Path

import portfolio
import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"


def read(p):
    return (ROOT / p).read_text()


def backticked(text):
    return re.findall(r"`([^`\n]+)`", text)


def path_like(token):
    return ("/" in token and not token.startswith(("http", "-", "$", "make ", "python", "bash", "git ", "terraform", "export", "source", "cosign", "sha256sum", "gitleaks"))
            and " " not in token and "<" not in token and "{" not in token and not token.startswith("--"))


def exists(token):
    token = token.rstrip("/").split(":")[0]
    return bool(glob.glob(str(ROOT / token))) or (ROOT / token).exists()


# ---- architecture
def test_architecture_has_three_mermaid_diagrams_that_are_well_formed():
    blocks = re.findall(r"```mermaid\n(.*?)```", read("docs/architecture.md"), re.S)
    assert len(blocks) == 3
    for b in blocks:
        assert b.lstrip().split()[0] in ("flowchart", "sequenceDiagram")
        for line in b.splitlines():
            assert line.count('"') % 2 == 0, f"unbalanced quote: {line}"
            assert line.count("[") == line.count("]"), f"unbalanced bracket: {line}"
        if b.lstrip().startswith("flowchart"):
            assert len(re.findall(r"^\s*subgraph ", b, re.M)) == len(re.findall(r"^\s*end\s*$", b, re.M)), "subgraph without end"


def test_every_path_in_the_architecture_component_table_exists():
    text = read("docs/architecture.md")
    table = text[text.index("## 4. Components"):text.index("## 5.")]
    tokens = [t for t in backticked(table) if path_like(t)]
    assert len(tokens) >= 10
    missing = [t for t in tokens if not exists(t)]
    assert not missing, missing


@pytest.mark.parametrize("doc", ["docs/architecture.md", "docs/threat-model.md", "docs/lessons-learned.md", "docs/real-aws.md",
                                 "docs/RELEASE.md", "docs/intel-contract.md", "README.md"])
def test_paths_named_in_a_document_exist(doc):
    missing = []
    for t in backticked(read(doc)):
        if path_like(t) and re.match(r"^[\w.*/-]+$", t) and t.split("/")[0] in ("docs", "terraform", "sentinel", "triage", "release", "response", "ops",
                                                                               "detections", "cloudpurple", "siem", "policies", "scripts", ".github"):
            if not exists(t):
                missing.append(t)
    assert not missing, f"{doc} names files that do not exist: {missing}"


# ---- ADRs
def test_adr_numbers_are_contiguous_and_complete():
    files = sorted((DOCS / "adr").glob("[0-9][0-9][0-9][0-9]-*.md"))
    nums = [int(f.name[:4]) for f in files]
    assert nums == list(range(1, len(nums) + 1)), nums
    for f in files:
        t = f.read_text()
        assert t.startswith(f"# ADR-{f.name[:4]}:") and "* Status:" in t and "* Date:" in t and "## Decision" in t, f.name
    assert f"decisions 0001 to {len(nums):04d}" in read("README.md")


def test_every_new_adr_is_referenced_from_somewhere():
    corpus = "".join(p.read_text() for p in DOCS.glob("*.md")) + read("README.md")
    for n in ("0019", "0020", "0021", "0022", "0023"):
        assert f"ADR-{n}" in corpus, n


# ---- README and evidence
def test_readme_numbers_match_the_evidence():
    assert portfolio.check(read("README.md"), portfolio.numbers()) == []


def test_generated_numbers_are_up_to_date():
    stored = json.loads((DOCS / "evidence" / "portfolio-numbers.json").read_text())
    assert stored == portfolio.numbers(), "run `make portfolio`"


def test_headline_files_exist():
    head = json.loads((DOCS / "evidence" / "headline.json").read_text())
    missing = [v for k, v in head.items() if not k.startswith("_") and not (DOCS / "evidence" / v).is_file()]
    assert not missing, missing


def test_the_cv_line_does_not_overclaim():
    text = (DOCS / "evidence" / "portfolio-numbers.md").read_text()
    cv = text.split("## CV line")[1]
    assert "human approval" not in cv and "simulated" in cv and "LocalStack" in cv


def test_readme_says_what_it_does_not_show():
    t = read("README.md")
    assert "## What this does not show" in t and "real AWS" in t and "simulated" in t and "S08" in t


def test_status_table_has_all_seven_stages():
    t = read("README.md")
    for n in range(1, 8):
        assert re.search(rf"^\| {n}\. ", t, re.M), f"stage {n} missing from the status table"


# ---- predictions
@pytest.mark.parametrize("f", sorted(glob.glob(str(DOCS / "stage*-predictions.md"))))
def test_no_unfilled_placeholder_in_a_predictions_file(f):
    assert not re.search(r"<(read|fill|todo|tbd)[^>]*>", Path(f).read_text(), re.I), f"{Path(f).name} has an unfilled placeholder"


# ---- make targets named in docs exist
def make_targets():
    out = set()
    for mk in [ROOT / "Makefile", *ROOT.glob("*/*.mk")]:
        out |= set(re.findall(r"^([A-Za-z0-9_-]+):", mk.read_text(), re.M))
    return out


@pytest.mark.parametrize("doc", ["README.md", "docs/demo-script.md", "docs/RELEASE.md", "docs/lessons-learned.md"])
def test_make_targets_named_in_a_document_exist(doc):
    targets = make_targets()
    named = set(re.findall(r"(?:`|^ {4}|^\| .*?`)make ([a-z][a-z0-9-]*)", read(doc), re.M))
    unknown = sorted(n for n in named if n not in targets)
    assert not unknown, f"{doc} names make targets that do not exist: {unknown}"


# ---- secrets scanning config stays narrow
def test_gitleaks_allowlist_is_by_value_not_by_source_path():
    t = read(".gitleaks.toml")
    assert "useDefault = true" in t
    paths = re.search(r"paths = \[(.*?)\]", t, re.S).group(1)
    assert "sentinel" not in paths and "triage" not in paths and "response" not in paths and "src" not in paths
    for rx in re.findall(r"'''(.*?)'''", re.search(r"regexes = \[(.*?)\]", t, re.S).group(1)):
        assert rx.startswith(("AKIA", "wJalr")) and "EXAMPLE" in rx or rx == "AKIAABCDEFGHIJKLMNOP"
