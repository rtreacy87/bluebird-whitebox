-- ============================================================
-- White-box recon pipeline schema
-- SQLite
--
-- Source of truth for pipeline database structure. Do not add
-- columns/tables ad hoc in application code without updating
-- this file first (see CLAUDE.md).
-- ============================================================

PRAGMA foreign_keys = ON;

-- ============================================================
-- STAGE 0: Deterministic structural index (ground truth)
-- Nothing derived from an LLM call may write to these tables.
-- ============================================================

CREATE TABLE files (
    file_id       INTEGER PRIMARY KEY,
    path          TEXT NOT NULL UNIQUE,
    sha256        TEXT NOT NULL,          -- detect if source changes between runs
    loc           INTEGER,
    token_count   INTEGER,                -- for context-budget decisions
    indexed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE symbols (
    symbol_id         INTEGER PRIMARY KEY,
    file_id           INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK(kind IN ('class','method','field','constructor')),
    name              TEXT NOT NULL,
    signature         TEXT,                   -- full method signature if applicable
    parent_symbol_id  INTEGER REFERENCES symbols(symbol_id), -- method -> class
    line_start        INTEGER,
    line_end          INTEGER,
    is_entrypoint     BOOLEAN NOT NULL DEFAULT 0 -- @GetMapping/@PostMapping etc.
);

CREATE TABLE call_edges (
    edge_id            INTEGER PRIMARY KEY,
    caller_symbol_id   INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    callee_symbol_id   INTEGER REFERENCES symbols(symbol_id), -- NULL if unresolved
    callee_raw_name    TEXT,               -- fallback when callee can't be resolved
    resolved           BOOLEAN NOT NULL DEFAULT 1, -- 0 = best-effort/unresolved
                                                     -- (cross-file, reflection, etc.)
    line_no            INTEGER
);

CREATE TABLE field_access (
    access_id     INTEGER PRIMARY KEY,
    symbol_id     INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE, -- method doing the access
    field_name    TEXT NOT NULL,
    owning_class  TEXT,
    access_type   TEXT NOT NULL CHECK(access_type IN ('read','write')),
    line_no       INTEGER
);

CREATE TABLE input_sources (
    source_id     INTEGER PRIMARY KEY,
    symbol_id     INTEGER NOT NULL REFERENCES symbols(symbol_id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK(kind IN ('RequestParam','PathVariable','RequestBody',
                                                'Header','Cookie','SessionAttribute')),
    param_name    TEXT,
    line_no       INTEGER
);

-- ============================================================
-- STAGE 1-4: LLM-derived analysis (never ground truth)
-- Every row here must be traceable to an llm_runs row for
-- provenance (model, prompt version, chunking).
-- ============================================================

CREATE TABLE llm_runs (
    run_id             INTEGER PRIMARY KEY,
    stage              TEXT NOT NULL CHECK(stage IN ('triage','audit','trace','dynamic_interpret')),
    model_name         TEXT NOT NULL,          -- exact Ollama tag, e.g. 'whiterabbitneo:latest'
    prompt_version     TEXT NOT NULL,          -- e.g. 'triage_v1'
    file_id            INTEGER REFERENCES files(file_id),
    started_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    input_token_count  INTEGER,
    num_ctx            INTEGER,                -- Ollama context length used for this call
    chunk_index        INTEGER NOT NULL DEFAULT 0,
    chunk_total        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE triage_results (
    result_id        INTEGER PRIMARY KEY,
    run_id           INTEGER NOT NULL REFERENCES llm_runs(run_id) ON DELETE CASCADE,
    symbol_id        INTEGER REFERENCES symbols(symbol_id), -- NULL if model referenced
                                                              -- a method not in symbols
    symbol_name_raw  TEXT,                  -- what the model actually said
                                             -- (required for hallucination check)
    has_input        BOOLEAN,               -- C1
    sink_type        TEXT CHECK(sink_type IN ('sql_unsafe','sql_safe','file_path',
                                               'command_exec','template','none')), -- C2
    validation_desc  TEXT,                  -- C3
    needs_trace      BOOLEAN NOT NULL DEFAULT 0, -- C4
    confidence       TEXT CHECK(confidence IN ('high','medium','low')),            -- C5
    missing_context  TEXT,                  -- what file/class was needed but absent
    notes            TEXT
);

CREATE TABLE audit_results (
    audit_id         INTEGER PRIMARY KEY,
    run_id           INTEGER NOT NULL REFERENCES llm_runs(run_id) ON DELETE CASCADE, -- the audit run itself
    audited_run_id   INTEGER NOT NULL REFERENCES llm_runs(run_id), -- the triage run being checked
    symbol_id        INTEGER REFERENCES symbols(symbol_id),
    status           TEXT NOT NULL CHECK(status IN ('matched','missing_from_table',
                                                      'hallucinated_row','ambiguous')),
    notes            TEXT
);

-- ============================================================
-- STAGE 3: Deterministic trace queue (sub-agent substitute)
-- ============================================================

CREATE TABLE trace_queue (
    queue_id                     INTEGER PRIMARY KEY,
    origin_triage_result_id      INTEGER NOT NULL REFERENCES triage_results(result_id),
    target_symbol_id             INTEGER REFERENCES symbols(symbol_id),
    target_variable              TEXT,
    status                       TEXT NOT NULL CHECK(status IN ('pending','in_progress',
                                                                  'done','blocked'))
                                       DEFAULT 'pending',
    assembled_context_symbol_ids TEXT,     -- JSON array of symbol_ids from graph walk
    created_at                   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE trace_results (
    trace_id             INTEGER PRIMARY KEY,
    queue_id             INTEGER NOT NULL REFERENCES trace_queue(queue_id) ON DELETE CASCADE,
    run_id                INTEGER NOT NULL REFERENCES llm_runs(run_id),
    verdict               TEXT NOT NULL CHECK(verdict IN ('exploitable_path','safe_path',
                                                            'insufficient_context','inconclusive')),
    path_narrative        TEXT,             -- step-by-step chain the model described
    evidence_symbol_ids   TEXT              -- JSON array, the actual path cited
);

-- ============================================================
-- STAGE 4.5: Dynamic verification (deterministic probe-firing
-- against a verified-local disposable replica; LLM involvement,
-- if any, is limited to interpreting an ambiguous probe result
-- and always goes through llm_runs for provenance, same as
-- every other LLM-derived table).
-- ============================================================

CREATE TABLE target_environments (
    env_id             INTEGER PRIMARY KEY,
    source_root        TEXT NOT NULL,              -- decompiled source root used
                                                     -- (e.g. ~/BlueBirdSourceCode)
    build_dir          TEXT NOT NULL,               -- recompiled classes output dir
    start_class        TEXT NOT NULL,               -- Start-Class read from the jar's
                                                     -- META-INF/MANIFEST.MF
    app_host           TEXT NOT NULL DEFAULT 'localhost',
    app_port           INTEGER NOT NULL,
    app_pid            INTEGER,                     -- PID of the background java process,
                                                     -- so teardown can find it across CLI calls
    app_log_path       TEXT NOT NULL,               -- where the app's stdout/stderr was
                                                     -- redirected, so probes.py can read
                                                     -- exactly what it logged per request
    db_container_name  TEXT,
    db_host            TEXT NOT NULL DEFAULT 'localhost',
    db_port            INTEGER,
    db_user            TEXT,               -- needed by probes.py to query the
                                            -- verify_table/verify_column row afterward
    db_name            TEXT,
    status             TEXT NOT NULL CHECK(status IN ('starting','running','stopped','failed'))
                             DEFAULT 'starting',
    started_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stopped_at         TIMESTAMP
);

CREATE TABLE dynamic_probe_batches (
    batch_id           INTEGER PRIMARY KEY,
    source_trace_id    INTEGER NOT NULL REFERENCES trace_results(trace_id),
                                                     -- the exploitable_path hypothesis
                                                     -- this battery is verifying
    input_source_id    INTEGER REFERENCES input_sources(source_id),
                                                     -- NULL for a second-order candidate
                                                     -- identified only via
                                                     -- trace_queue.target_variable (no
                                                     -- direct request param of its own)
    target_param_name  TEXT NOT NULL,               -- the actual form/query param name fired
    env_id             INTEGER NOT NULL REFERENCES target_environments(env_id),
    endpoint           TEXT NOT NULL,                -- e.g. '/signup'
    http_method        TEXT NOT NULL CHECK(http_method IN ('GET','POST')),
    order_hypothesis   TEXT NOT NULL CHECK(order_hypothesis IN ('first_order','second_order')),
    verify_table       TEXT,                          -- DB table to check for the probe's
                                                        -- resulting row (human-supplied via
                                                        -- request-templates.json)
    verify_column      TEXT,                           -- DB column to check
    started_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE dynamic_probe_results (
    probe_id               INTEGER PRIMARY KEY,
    batch_id               INTEGER NOT NULL REFERENCES dynamic_probe_batches(batch_id)
                                 ON DELETE CASCADE,
    probe_name             TEXT NOT NULL CHECK(probe_name IN ('baseline','single_quote',
                                                                'double_quote','backslash')),
    input_value            TEXT NOT NULL,             -- exact value sent for this probe
    http_status            INTEGER,
    response_snippet       TEXT,                       -- truncated response body
    app_log_snippet        TEXT,                       -- tail of the target app's own console
                                                        -- log around the time of the request
    db_row_snippet         TEXT,                       -- verify_table/verify_column value found
                                                        -- afterward, if any
    classification         TEXT NOT NULL CHECK(classification IN ('error','passthrough_unmodified',
                                                                    'transformed','rejected','ambiguous'))
                                 DEFAULT 'ambiguous',
    interpreted_by_run_id  INTEGER REFERENCES llm_runs(run_id),
                                                        -- set only when an ambiguous result was
                                                        -- resolved by the local-LLM interpretation
                                                        -- pass (interpret.py) -- never set for the
                                                        -- other four deterministic classifications
    notes                  TEXT,
    created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- STAGE 5-6: Human verification + final findings
-- Only findings with verified_by_human=1 AND status='confirmed'
-- should ever leave the DB in an exported report.
-- ============================================================

CREATE TABLE findings (
    finding_id              INTEGER PRIMARY KEY,
    source_trace_id         INTEGER REFERENCES trace_results(trace_id),        -- nullable:
                                                                                 -- may originate from triage alone
    source_triage_result_id INTEGER REFERENCES triage_results(result_id),
    endpoint                TEXT,                    -- e.g. '/find-user'
    vuln_class              TEXT,                    -- e.g. 'blind_sqli','error_based','second_order'
    verified_by_human       BOOLEAN NOT NULL DEFAULT 0,
    verification_method     TEXT CHECK(verification_method IN ('live_debug','query_log',
                                                                  'manual_payload', NULL)),
    verification_notes      TEXT,
    severity                TEXT,
    status                  TEXT NOT NULL CHECK(status IN ('confirmed','rejected','needs_review'))
                                  DEFAULT 'needs_review',
    reviewed_at             TIMESTAMP
);

-- ============================================================
-- Indexes
-- Support the coverage/hallucination queries described in
-- CLAUDE.md, plus common lookups during the pipeline run.
-- ============================================================

-- Coverage check: LEFT JOIN symbols -> triage_results to find
-- reviewed vs. unreviewed methods.
CREATE INDEX idx_triage_symbol_id       ON triage_results(symbol_id);
CREATE INDEX idx_symbols_file_id        ON symbols(file_id);
CREATE INDEX idx_symbols_kind           ON symbols(kind);

-- Hallucination check: symbol_id IS NULL rows in triage_results.
CREATE INDEX idx_triage_run_id          ON triage_results(run_id);

-- Audit cross-referencing.
CREATE INDEX idx_audit_audited_run_id   ON audit_results(audited_run_id);
CREATE INDEX idx_audit_symbol_id        ON audit_results(symbol_id);

-- Call graph traversal (Stage 3 context assembly).
CREATE INDEX idx_call_edges_caller      ON call_edges(caller_symbol_id);
CREATE INDEX idx_call_edges_callee      ON call_edges(callee_symbol_id);
CREATE INDEX idx_call_edges_resolved    ON call_edges(resolved);

-- Field flow tracing (second-order vulnerability detection).
CREATE INDEX idx_field_access_name      ON field_access(field_name);
CREATE INDEX idx_field_access_symbol_id ON field_access(symbol_id);

-- Trace queue processing.
CREATE INDEX idx_trace_queue_status     ON trace_queue(status);
CREATE INDEX idx_trace_results_queue_id ON trace_results(queue_id);

-- Findings export filter (verified_by_human=1 AND status='confirmed').
CREATE INDEX idx_findings_status        ON findings(status, verified_by_human);

-- Input source lookup (entry points into the codebase).
CREATE INDEX idx_input_sources_symbol   ON input_sources(symbol_id);
CREATE INDEX idx_symbols_entrypoint     ON symbols(is_entrypoint);

-- Dynamic verification lookups (Stage 4.5).
CREATE INDEX idx_dynamic_batches_trace_id  ON dynamic_probe_batches(source_trace_id);
CREATE INDEX idx_dynamic_batches_env_id    ON dynamic_probe_batches(env_id);
CREATE INDEX idx_dynamic_results_batch_id  ON dynamic_probe_results(batch_id);
CREATE INDEX idx_dynamic_results_class     ON dynamic_probe_results(classification);
