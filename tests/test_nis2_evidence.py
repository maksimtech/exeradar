"""What docs/nis2-compliance.md tells a customer has to stay true of this code.

The document answers the seven questions a customer subject to NIS2 (directive
2022/2555, in Italy d.lgs. 138/2024) can ask a software supplier, and a customer
reads it as evidence. Every statement in it that the repository can prove is
checked here, so that the document goes red when the code moves away from it
instead of quietly turning false: the hosts the tool contacts, the user the image
runs as, the cache it writes, the files each release carries, the scanners it
names, and the words a supplier cannot honestly use.

What the repository cannot prove is not claimed as proven. The required status
checks live in GitHub's settings, so the document gives the date they were read
on; there is no penetration test, so the document says there is none.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

from exeradar import law_cache

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "exeradar"
DOC = ROOT / "docs" / "nis2-compliance.md"
SECURITY = ROOT / "SECURITY.md"
README = ROOT / "README.md"
DOCKERFILE = ROOT / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"
EVIDENCE = WORKFLOWS / "sbom.yml"
DOCKER = WORKFLOWS / "docker.yml"

# A module that imports one of these can reach the network; one that does not
# cannot, whatever URLs its constants mention (tlp.py cites the FIRST standard in
# reports, tlds.py the IANA list it was generated from, strings.py the URL shapes
# it looks for inside a binary).
NETWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(?:httpx|smtplib|dns|requests|urllib\.request|socket)\b", re.M
)
URL_HOST = re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# The contact URL every request carries in its User-Agent. It names this
# repository; nothing is sent to it.
USER_AGENT_LINK = re.compile(r"\(\+https://github\.com/maksimtech/")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def hosts_in_code() -> dict[str, set[str]]:
    """Fixed hosts named in string constants of the modules that can reach the network.

    ExeRadar reads the file it analyses from disk and sends nothing about it:
    every host it contacts has a fixed name.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not NETWORK_IMPORT.search(source):
            continue
        tree = ast.parse(source)
        skip = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in skip or USER_AGENT_LINK.search(node.value):
                continue
            for host in URL_HOST.findall(node.value):
                found.setdefault(host.lower().rstrip("."), set()).add(path.name)
    return found


def section(text: str, name: str) -> str:
    """The text between `<!-- name:start -->` and `<!-- name:end -->`."""
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.S)
    assert match, f"docs/nis2-compliance.md has no {name} section between its markers"
    return match.group(1)


def table_first_column(block: str) -> set[str]:
    """The backticked value in the first cell of every row of a markdown table."""
    values = set()
    for line in block.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and cells and cells[0].startswith("`"):
            values.add(cells[0].strip("`"))
    return values


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


# --- Question 3: what leaves the machine ------------------------------------


def test_every_host_the_code_contacts_is_declared_and_no_other(doc):
    declared = table_first_column(section(doc, "hosts"))
    in_code = set(hosts_in_code())
    assert declared == in_code, (
        f"declared but not in the code: {sorted(declared - in_code)}; "
        f"in the code but not declared: {sorted(in_code - declared)}"
    )


def test_the_host_rule_looks_at_something():
    """A rule that found no host would pass for the wrong reason."""
    assert len(hosts_in_code()) >= 3


def test_the_host_rule_skips_what_is_only_cited():
    """Every request names github.com/maksimtech/exeradar in its User-Agent;
    tlp.py prints www.first.org/tlp in reports; tlds.py was generated from
    data.iana.org; strings.py holds example.com and the like as patterns. None of
    them is a host the tool talks to."""
    hosts = hosts_in_code()
    for cited in ("github.com", "www.first.org", "data.iana.org", "example.com"):
        assert cited not in hosts


def test_the_cache_declared_is_the_one_written(doc, monkeypatch, tmp_path):
    monkeypatch.delenv("EXERADAR_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    written = law_cache.default_cache_path().relative_to(tmp_path).as_posix()
    assert f"~/{written}" in doc
    assert "EXERADAR_HOME" in doc


def test_analysis_is_offline_unless_asked(doc):
    """The document says analysing a file contacts nothing unless --online is
    given; the command has to keep that default."""
    cli = (PACKAGE / "cli.py").read_text(encoding="utf-8")
    assert re.search(r'online: bool = typer\.Option\(\s*False, "--online"', cli)
    assert "offline=not online" in cli
    assert "--online" in doc
    assert "exeradar psirt" in doc


def test_the_signature_check_windows_does_is_declared(doc):
    """On Windows the catalog path asks the operating system, and Windows may reach
    the CA's servers to build the chain and check revocation. ExeRadar does not
    make those requests, but it causes them, so the document says so."""
    signature = (PACKAGE / "signature.py").read_text(encoding="utf-8")
    assert "Get-AuthenticodeSignature" in signature
    assert "`Get-AuthenticodeSignature`" in doc


# --- Question 2: who the container runs as -----------------------------------


def test_the_image_runs_as_the_user_the_document_names(doc):
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    user = re.findall(r"^USER\s+(\S+)", dockerfile, re.M)[-1]
    uid = re.search(rf"useradd\b[^\n]*-u\s+(\d+)[^\n]*\b{re.escape(user)}\b", dockerfile)
    assert user not in {"root", "0"}
    assert uid, f"the Dockerfile does not create {user} with an explicit UID"
    assert f"UID {uid.group(1)}" in doc
    assert f"`{user}`" in doc


# --- Questions 1 and 6: what every release carries ---------------------------


@pytest.fixture(scope="module")
def evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_the_evidence_follows_the_image_of_a_release(evidence):
    """The image SBOM and its scan describe the image of the tag, so the job
    runs when that image has been pushed — not when the tag is, when it does not
    exist yet."""
    triggers = evidence.get(True, evidence.get("on"))
    docker_name = yaml.safe_load(DOCKER.read_text(encoding="utf-8"))["name"]
    assert triggers["workflow_run"]["workflows"] == [docker_name]
    assert triggers["workflow_run"]["types"] == ["completed"]
    assert "tag" in triggers["workflow_dispatch"]["inputs"]
    job = next(iter(evidence["jobs"].values()))
    assert "conclusion == 'success'" in job["if"]
    assert "startsWith(github.event.workflow_run.head_branch, 'v')" in job["if"]


def test_the_evidence_job_pins_its_actions():
    for line in EVIDENCE.read_text(encoding="utf-8").splitlines():
        if "uses:" in line:
            ref = line.split("uses:", 1)[1].split("#")[0].strip()
            assert re.search(r"@[0-9a-f]{40}$", ref), f"not pinned to a commit: {line.strip()}"


def test_the_release_carries_the_files_the_document_promises(doc):
    promised = table_first_column(section(doc, "assets"))
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert promised, "the document promises no release file"
    for name in promised:
        stem = name.split("<")[0].rstrip("-")
        assert stem in workflow, f"{name} is promised but sbom.yml never writes {stem}"
    assert "gh release upload" in workflow


def test_the_scan_is_not_presented_as_a_penetration_test(doc):
    """Question 6 asks for a penetration test. There has been none, and a scan of
    known CVEs is not one: the release note that travels with the files says so."""
    assert "non è un penetration test" in " ".join(doc.split())
    assert "not a penetration test" in EVIDENCE.read_text(encoding="utf-8")


# --- Questions 4 and 5: policy and pipeline ----------------------------------

SCANNERS = {
    "CodeQL": "codeql",
    "Bandit": "bandit",
    "Trivy": "trivy",
    "Snyk": "snyk",
    "Docker Scout": "docker-scout",
    "SonarCloud": "sonarcloud",
    "Security Posture": "security-posture",
    "mutmut": "mutation",
}


def test_every_scanner_named_has_its_workflow_and_none_is_left_out(doc):
    named = table_first_column(section(doc, "scanners"))
    assert named <= set(SCANNERS), f"unknown scanner names: {sorted(named - set(SCANNERS))}"
    for name in named:
        assert (WORKFLOWS / f"{SCANNERS[name]}.yml").is_file(), f"{name} has no workflow"
    present = {n for n, w in SCANNERS.items() if (WORKFLOWS / f"{w}.yml").is_file()}
    assert present <= named, f"workflows the document does not name: {sorted(present - named)}"


def test_security_md_answers_the_fourth_question():
    text = SECURITY.read_text(encoding="utf-8")
    for heading in (
        "## Reporting a vulnerability",
        "## How vulnerabilities are found",
        "## Response times",
        "## Customer notification",
        "## Rollback",
    ):
        assert heading in text, f"SECURITY.md has no {heading!r}"
    assert "single maintainer" in text


def test_the_document_and_security_md_give_the_same_contact(doc):
    contact = re.search(r"[\w.+-]+@maksimtech\.com", SECURITY.read_text(encoding="utf-8"))
    assert contact
    assert contact.group(0) in doc


def test_the_document_does_not_claim_a_second_review(doc):
    """The repository has one maintainer and its ruleset has no pull request rule.
    Question 5 asks for a second reviewer; the honest answer is that there is none."""
    prose = " ".join(doc.split())
    assert "manutentore unico" in prose
    assert "nessuna revisione obbligatoria da parte di una seconda persona" in prose


FORBIDDEN = [
    re.compile(r"NIS2[- ](?:ready|compliant|certified)", re.I),
    re.compile(r"certificat\w* NIS2", re.I),
    re.compile(r"nessun dato (?:è )?inviato a terzi", re.I),
    re.compile(r"no data (?:is )?sent to third parties", re.I),
    re.compile(r"ogni PR richiede", re.I),
]


@pytest.mark.parametrize("path", [DOC, SECURITY, README], ids=lambda p: p.name)
def test_no_claim_this_repository_cannot_back(path):
    text = path.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        assert not pattern.search(text), f"{path.name} says {pattern.search(text).group(0)!r}"


# --- Question 1: the licence gate the document cites --------------------------


def test_the_licence_gate_matches_the_names_packages_actually_declare():
    """Without --partial-match, pip-licenses fails only on a licence string equal
    to "GPL", and no package declares that: they declare classifiers such as
    "GNU Lesser General Public License v2 or later (LGPLv2+)". Measured on
    2026-10-11 with chardet 5.2.0 installed: `--fail-on="GPL;AGPL;LGPL"` exited 0,
    the same with --partial-match exited 1. The gate had never refused anything."""
    licences = (WORKFLOWS / "licenses.yml").read_text(encoding="utf-8")
    gate = next(line for line in licences.splitlines() if "--fail-on" in line)
    assert "--partial-match" in gate


# --- The lockfile the document points to ------------------------------------


def test_quality_keeps_the_lockfile_in_step_with_pyproject():
    """ExeRadar had no uv.lock until 2026-10-11. A lockfile shown to a customer as
    the list of dependencies has to be the current one, so the check that keeps it
    current came with it."""
    quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
    assert re.search(r"uv(?:==[\d.]+)?\s.*lock --check|uv lock --check", quality)
