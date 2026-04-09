Show recent security alerts from MacCrab.

Use the maccrab MCP server `get_alerts` tool with `{"limit": 20, "hours": 24}` to get recent alerts.

For each alert:
- Explain what the detection means in plain language
- Rate the risk (critical alerts first)
- Suggest specific next steps

If there are campaigns detected, also call `get_campaigns` and explain the attack patterns.

Group alerts by category (persistence, credential access, C2, etc.) for clarity.
