# MCP client contract

MacCrab's server advertises MCP protocol `2024-11-05` over newline-delimited JSON-RPC on standard input/output. Clients initialize, accept the returned protocol version, then send `notifications/initialized` before normal operations. Logging belongs on stderr; stdout carries protocol messages. These are the archived protocol's [transport](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports) and [lifecycle](https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle) contracts.

This document describes the implemented stdio surface. It does not claim HTTP/SSE/Streamable HTTP support or compatibility with a named client's current release. Installed client/version validation remains part of release qualification.

`get_status` and `list_rules` return schema-1 JSON in their text content blocks, sharing the CLI models documented in [CLI_JSON.md](CLI_JSON.md). Tool failures set `isError: true`; an empty successful result is distinct from a read failure. Status queries use bounded physical event counts. Current health and rule counters require fresh observations from the same engine process.

`get_status.agent_trace_trust` is `unauthenticated_self_reported`: local OTLP spans are advisory self-reports, not authenticated kernel evidence. The independent `current_health.traces_storage_admission` block preserves receiver/storage admission and reported shedding. It is omitted with stale or unavailable current health; the fixed trust label does not imply healthy or enabled collection.

`list_rules` filters by `level`, `tactic` and `search`. `offset` is zero based within that filtered inventory; `limit` defaults to 100 and is bounded to 1–500. Results include total/filtered counts and `next_offset` (null on the last page). Pagination is a fresh read per request rather than a retained snapshot, so a concurrently edited corpus may change between pages.

`get_daemon_config` reads configured values by default. Set `effective: true` to read non-secret effective runtime tunables and applied generation. Provide `request_id` to read a durable configuration/reload receipt. `set_daemon_config` and `reload_rules` return a pending request ID; acceptance and completion require a later receipt read. Their existing capability gates remain in force. Shared numeric bounds, value types and disable-only restrictions are revalidated by the daemon.

The ordinary local contract fixtures cover populated event/alert counts through the CLI executable and MCP read handlers, rule pagination, current/previous-epoch telemetry, empty corpus, configured defaults and read failures. Existing stdio harness tests cover initialization and tool discovery. These layers are useful regression checks; they do not substitute for running the signed release with a supported client against representative installed data in configured and no-LLM modes.
