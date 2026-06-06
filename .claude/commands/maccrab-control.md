Help the user customise MacCrab through the agent control-plane (MCP).

First, call `agent_capabilities` to see which tiers (config / authoring / response)
the human has enabled — all are off by default and only the human can turn them on
(dashboard Settings → Agent Control). If the user asks for a change whose tier is
off, tell them exactly which toggle to flip; do not attempt the change.

Then, based on the request:

- **Tune a built-in detection** (tier: config): `list_builtin_rules` to find the
  `maccrab.*` id, then `set_builtin_rule_setting` to mute it (`enabled:false`) or
  override severity. Detection still runs when an alert is muted.
- **Author/remove a rule** (tier: authoring): `create_rule` with one Sigma YAML
  rule (`product: macos`), or `delete_rule` for a user-authored rule. The compiler
  validates before install; report compile errors verbatim.
- **Change a daemon setting** (tier: config, or response for kill-switches):
  `set_daemon_config`. Call with an invalid key once to print the allow-list.
- **Reload / refresh** (tier: config): `reload_rules`, `refresh_threat_intel`.
- **Review what changed**: `get_audit_log`.

Safety: every change is audit-logged and queued (effect within ~5 s; config on next
reload). Response actions never auto-execute. Built-in detections are tuned, never
deleted. Summarise what you changed and how to verify it.
