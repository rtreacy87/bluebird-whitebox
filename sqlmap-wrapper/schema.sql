-- Schema for sqlmap-wrapper's own SQLite DB (sqlmap-wrapper/data/wrapper.db).
-- Separate database file from bluebird-whitebox/data/recon.db by design --
-- see CLAUDE.md and DATA_DICTIONARY.md for why this tool is a distinct,
-- separately-governed subtree rather than an extension of that repo's own
-- schema.

PRAGMA foreign_keys = ON;

-- ============================================================
-- Target registration: the wrapper's guard-equivalent of
-- bluebird-whitebox's hardcoded-localhost check. Real targets aren't
-- localhost by definition, so the guard here is "must match a row a human
-- explicitly registered and marked authorized", not a fixed allowlist.
-- ============================================================

CREATE TABLE targets (
    target_id     INTEGER PRIMARY KEY,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    label         TEXT,                          -- e.g. 'HTB-BlueBird-10.10.11.x'
    authorized    BOOLEAN NOT NULL DEFAULT 0,     -- explicit human opt-in, no expiry (see DATA_DICTIONARY.md)
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port)
);

-- ============================================================
-- Imported Stage 6 candidate exports and the candidates within them.
-- ============================================================

CREATE TABLE import_batches (
    import_id       INTEGER PRIMARY KEY,
    source_file     TEXT NOT NULL,                -- path to the Stage 6 JSON export
    schema_version  TEXT NOT NULL,
    imported_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    candidate_count INTEGER NOT NULL
);

CREATE TABLE candidates (
    candidate_id       INTEGER PRIMARY KEY,
    import_id          INTEGER NOT NULL REFERENCES import_batches(import_id) ON DELETE CASCADE,
    target_id          INTEGER REFERENCES targets(target_id),   -- set at registration, not import
    finding_id_source  INTEGER NOT NULL,   -- bluebird-whitebox findings.finding_id -- NOT a real FK,
                                            -- cross-database by design, see DATA_DICTIONARY.md
    endpoint           TEXT NOT NULL,
    http_method        TEXT CHECK(http_method IS NULL OR http_method IN ('GET','POST')),
    vuln_class         TEXT,
    severity           TEXT,
    order_hypothesis   TEXT CHECK(order_hypothesis IS NULL OR order_hypothesis IN ('first_order','second_order')),
    target_param_name  TEXT,
    param_defaults_json TEXT,              -- sibling request-body values from request-templates.json,
                                            -- null if Stage 6 had no matching template at export time
    dbms_hint          TEXT,
    evidence_json      TEXT NOT NULL       -- the full evidence object, preserved verbatim
);

-- ============================================================
-- Real sqlmap invocations (or dry-run previews) and this tool's own LLM
-- provenance, mirroring bluebird-whitebox's llm_runs pattern but scoped to
-- this tool's one interpretation stage.
-- ============================================================

CREATE TABLE sqlmap_runs (
    run_id        INTEGER PRIMARY KEY,
    candidate_id  INTEGER NOT NULL REFERENCES candidates(candidate_id),
    target_id     INTEGER NOT NULL REFERENCES targets(target_id),
    argv_json     TEXT NOT NULL,           -- exact argv executed (or would execute, if dry_run)
    output_dir    TEXT NOT NULL,
    dry_run       BOOLEAN NOT NULL DEFAULT 1,
    exit_code     INTEGER,
    started_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at   TIMESTAMP
);

CREATE TABLE wrapper_llm_runs (
    run_id         INTEGER PRIMARY KEY,
    stage          TEXT NOT NULL CHECK(stage IN ('sqlmap_interpret')),
    model_name     TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    started_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sqlmap_results (
    result_id             INTEGER PRIMARY KEY,
    run_id                INTEGER NOT NULL REFERENCES sqlmap_runs(run_id) ON DELETE CASCADE,
    result_type           TEXT NOT NULL CHECK(result_type IN ('confirmed','not_confirmed','error','inconclusive')),
    summary_text          TEXT,
    raw_output_path       TEXT,             -- pointer to the file on disk, not an embedded blob
    interpreted_by_run_id INTEGER REFERENCES wrapper_llm_runs(run_id)
);

-- ============================================================
-- Indexes
-- ============================================================

CREATE INDEX idx_candidates_import_id      ON candidates(import_id);
CREATE INDEX idx_candidates_target_id      ON candidates(target_id);
CREATE INDEX idx_sqlmap_runs_candidate_id  ON sqlmap_runs(candidate_id);
CREATE INDEX idx_sqlmap_results_run_id     ON sqlmap_results(run_id);
