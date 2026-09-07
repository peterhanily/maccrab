-- Historical EventStore schema from v1.21.5 (4f9ab9b).
-- SQL copied from the shipped baseline and migrations through version 6.
-- The session index is created after its promoted column, as on a reopened store.

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                event_category TEXT NOT NULL, event_type TEXT NOT NULL,
                event_action TEXT NOT NULL, severity TEXT NOT NULL,
                process_pid INTEGER, process_name TEXT, process_path TEXT,
                process_commandline TEXT, process_ppid INTEGER,
                process_signer TEXT, process_team_id TEXT, process_signing_id TEXT,
                file_path TEXT, file_action TEXT,
                network_dest_ip TEXT, network_dest_port INTEGER,
                tcc_service TEXT, tcc_client TEXT, raw_json TEXT NOT NULL
            );

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category);

CREATE INDEX IF NOT EXISTS idx_events_process_path ON events(process_path);

CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE INDEX IF NOT EXISTS idx_events_ts_severity ON events(timestamp, severity);

CREATE INDEX IF NOT EXISTS idx_events_ts_category ON events(timestamp, event_category);

CREATE INDEX IF NOT EXISTS idx_events_process_ts ON events(process_path, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_ts_sev_cat ON events(timestamp, severity, event_category);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                process_name, process_path, process_commandline,
                file_path, network_dest_ip, tcc_service, tcc_client,
                content=events, content_rowid=rowid
            );

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END;

CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
                INSERT INTO events_fts(events_fts, rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES ('delete', old.rowid, old.process_name, old.process_path, old.process_commandline,
                    old.file_path, old.network_dest_ip, old.tcc_service, old.tcc_client);
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END;

ALTER TABLE events ADD COLUMN mcp_server_name TEXT;

ALTER TABLE events ADD COLUMN mcp_server_category TEXT;

ALTER TABLE events ADD COLUMN ai_tool_session_id TEXT;

CREATE INDEX IF NOT EXISTS idx_events_mcp_server ON events(timestamp, mcp_server_name);

CREATE TABLE IF NOT EXISTS alert_evidence (
                    alert_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    process_pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    process_commandline TEXT,
                    process_ppid INTEGER,
                    process_signer TEXT,
                    process_team_id TEXT,
                    process_signing_id TEXT,
                    file_path TEXT,
                    file_action TEXT,
                    network_dest_ip TEXT,
                    network_dest_port INTEGER,
                    tcc_service TEXT,
                    tcc_client TEXT,
                    raw_json TEXT NOT NULL,
                    mcp_server_name TEXT,
                    mcp_server_category TEXT,
                    ai_tool_session_id TEXT,
                    PRIMARY KEY (alert_id, id)
                );

CREATE INDEX IF NOT EXISTS idx_evidence_alert_ts ON alert_evidence(alert_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_evidence_event ON alert_evidence(id);

CREATE TABLE IF NOT EXISTS event_aggregates (
                    day TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    process_signer TEXT NOT NULL DEFAULT '',
                    process_path TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL,
                    PRIMARY KEY (day, event_category, process_signer, process_path)
                );

CREATE INDEX IF NOT EXISTS idx_aggregates_day ON event_aggregates(day);

CREATE INDEX IF NOT EXISTS idx_aggregates_day_category ON event_aggregates(day, event_category);

ALTER TABLE events ADD COLUMN agent_trace_id TEXT;

ALTER TABLE events ADD COLUMN agent_span_id TEXT;

ALTER TABLE events ADD COLUMN agent_tool TEXT;

ALTER TABLE events ADD COLUMN machine_agent_confidence TEXT;

ALTER TABLE events ADD COLUMN agent_evidence_json TEXT;

CREATE INDEX IF NOT EXISTS idx_events_trace ON events(agent_trace_id) WHERE agent_trace_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS attribution_overrides (
                    event_id TEXT PRIMARY KEY,
                    machine_confidence TEXT,
                    user_verdict TEXT NOT NULL,
                    user_note TEXT,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

CREATE INDEX IF NOT EXISTS idx_overrides_verdict ON attribution_overrides(user_verdict);

CREATE INDEX IF NOT EXISTS idx_overrides_updated ON attribution_overrides(updated_at);

ALTER TABLE events ADD COLUMN user_id INTEGER;

ALTER TABLE events ADD COLUMN user_name TEXT;

ALTER TABLE events ADD COLUMN group_id INTEGER;

ALTER TABLE events ADD COLUMN working_directory TEXT;

ALTER TABLE events ADD COLUMN responsible_pid INTEGER;

ALTER TABLE events ADD COLUMN architecture TEXT;

ALTER TABLE events ADD COLUMN is_platform_binary INTEGER;

ALTER TABLE events ADD COLUMN is_notarized INTEGER;

ALTER TABLE events ADD COLUMN process_sha256 TEXT;

ALTER TABLE events ADD COLUMN parent_name TEXT;

ALTER TABLE events ADD COLUMN parent_executable TEXT;

ALTER TABLE events ADD COLUMN parent_signer_type TEXT;

ALTER TABLE events ADD COLUMN ai_tool TEXT;

ALTER TABLE events ADD COLUMN ai_tool_child INTEGER;

ALTER TABLE events ADD COLUMN session_launch_source TEXT;

ALTER TABLE events ADD COLUMN tcc_decision TEXT;

CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);

CREATE INDEX IF NOT EXISTS idx_events_ai_tool_ts ON events(ai_tool, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_parent_exe_ts ON events(parent_executable, timestamp);

CREATE INDEX IF NOT EXISTS idx_events_ai_session ON events(ai_tool_session_id, timestamp) WHERE ai_tool_session_id IS NOT NULL;

PRAGMA user_version = 6;
