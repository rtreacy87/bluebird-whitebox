"""Stage 0 regression test against the BlueBird corpus (CLAUDE.md Testing section).

Structural completeness is checked with a deterministic, parser-based method
count compared against what actually landed in the DB -- not a manual read of
output. This corpus lives outside the repo (~/BlueBirdSourceCode is a
read-only decompiled artifact per CLAUDE.md), so these tests skip cleanly if
it isn't present rather than failing.
"""

import glob
from pathlib import Path

import pytest
import javalang

from pipeline import db
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage0_index.parser import parse_source

CORPUS_ROOT = Path("~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird").expanduser()

pytestmark = pytest.mark.skipif(
    not CORPUS_ROOT.exists(),
    reason=f"BlueBird regression corpus not found at {CORPUS_ROOT}",
)


@pytest.fixture(scope="module")
def indexed_conn(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("stage0") / "recon.db"
    conn = db.connect(str(db_path))
    stats = index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)
    assert stats["files_failed"] == 0, "no source file should fail to parse"
    return conn


def _independent_method_count():
    """Re-derive the method+constructor count directly from javalang, bypassing
    pipeline/stage0_index entirely, as the ground truth the DB is checked against."""
    count = 0
    for path in glob.glob(str(CORPUS_ROOT / "**" / "*.java"), recursive=True):
        tree = javalang.parse.parse(Path(path).read_text())
        for type_decl in tree.types:
            if not isinstance(type_decl, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                continue
            for member in type_decl.body:
                if isinstance(member, (javalang.tree.MethodDeclaration, javalang.tree.ConstructorDeclaration)):
                    count += 1
    return count


def test_no_files_failed_to_parse(indexed_conn):
    row = indexed_conn.execute("SELECT COUNT(*) AS n FROM files").fetchone()
    assert row["n"] == 14


def test_method_count_matches_independent_parse(indexed_conn):
    expected = _independent_method_count()
    actual = indexed_conn.execute(
        "SELECT COUNT(*) AS n FROM symbols WHERE kind IN ('method','constructor')"
    ).fetchone()["n"]
    assert actual == expected


def test_reindex_is_idempotent(tmp_path):
    conn = db.connect(str(tmp_path / "recon.db"))
    stats1 = index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)
    symbol_count_1 = conn.execute("SELECT COUNT(*) AS n FROM symbols").fetchone()["n"]

    stats2 = index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)
    symbol_count_2 = conn.execute("SELECT COUNT(*) AS n FROM symbols").fetchone()["n"]

    assert stats1["files_indexed"] == 14
    assert stats2["files_indexed"] == 0
    assert stats2["files_unchanged"] == 14
    assert symbol_count_1 == symbol_count_2


@pytest.mark.parametrize(
    "method_name,expected_kind,expected_param",
    [
        ("findUser", "RequestParam", "u"),
        ("forgotPOST", "RequestParam", "email"),
        ("profile", "PathVariable", "id"),
    ],
)
def test_known_vuln_entrypoints_have_input_sources(indexed_conn, method_name, expected_kind, expected_param):
    """Structural precondition for the three CLAUDE.md regression-gate vulns:
    Stage 0 must see them as entrypoints with the documented input source
    before Stage 1/2 can be expected to triage them at all."""
    row = indexed_conn.execute(
        "SELECT symbol_id, is_entrypoint FROM symbols WHERE name = ? AND kind = 'method'",
        (method_name,),
    ).fetchone()
    assert row is not None, f"{method_name} symbol not found"
    assert row["is_entrypoint"] == 1

    sources = indexed_conn.execute(
        "SELECT kind, param_name FROM input_sources WHERE symbol_id = ?", (row["symbol_id"],)
    ).fetchall()
    assert any(s["kind"] == expected_kind and s["param_name"] == expected_param for s in sources)


def test_entrypoint_count_matches_mapping_annotations(indexed_conn):
    # 15 @*Mapping-annotated methods across the 5 controllers (see EXPECTED_FINDINGS.md / manual count).
    row = indexed_conn.execute("SELECT COUNT(*) AS n FROM symbols WHERE is_entrypoint = 1").fetchone()
    assert row["n"] == 15


def test_unresolved_framework_calls_preserve_raw_name(indexed_conn):
    """Ground-truth invariant from CLAUDE.md: unresolved calls must never be
    silently dropped or collapsed -- callee_raw_name must survive."""
    row = indexed_conn.execute(
        "SELECT ce.resolved, ce.callee_raw_name FROM call_edges ce "
        "JOIN symbols s ON s.symbol_id = ce.caller_symbol_id "
        "WHERE s.name = 'forgotPOST' AND ce.callee_raw_name LIKE '%queryForObject%'"
    ).fetchone()
    assert row is not None
    assert row["resolved"] == 0
    assert row["callee_raw_name"] == "this.jdbcTemplate.queryForObject"


def test_same_class_call_resolves_intra_file(indexed_conn):
    """resetGET calls this.verifyResetCode -- both defined in AuthController.java,
    so Stage 0 (intra-file only) must resolve this one, unlike framework calls."""
    row = indexed_conn.execute(
        "SELECT ce.resolved, callee.name AS callee_name FROM call_edges ce "
        "JOIN symbols caller ON caller.symbol_id = ce.caller_symbol_id "
        "JOIN symbols callee ON callee.symbol_id = ce.callee_symbol_id "
        "WHERE caller.name = 'resetGET' AND ce.callee_raw_name LIKE '%verifyResetCode%'"
    ).fetchone()
    assert row is not None
    assert row["resolved"] == 1
    assert row["callee_name"] == "verifyResetCode"


def test_parser_matches_indexer_for_single_file():
    """parser.py (pure) and indexer.py (DB-writing) must agree on symbol
    counts for a single file, independent of the whole-corpus fixture above."""
    path = CORPUS_ROOT / "controller" / "ProfileController.java"
    parsed = parse_source(str(path), path.read_text())
    assert len(parsed.symbols) == 6  # 1 class + 2 fields + 3 methods
