Check this machine's security posture using MacCrab.

Use the maccrab MCP server tools to:

1. Call `get_status` to check if the daemon is running and get basic stats
2. Call `get_security_score` to get the full security posture score with factors
3. Call `get_alerts` with `{"severity": "high", "limit": 10}` to check for active threats
4. Call `get_campaigns` to check for multi-stage attack patterns

Summarize the findings in a clear report:
- Overall security grade and score
- Any active threats or campaigns that need attention
- Top 3 recommendations to improve the score
- Whether the daemon is running and healthy

If the maccrab MCP server is not available, suggest building it: `swift build --target maccrab-mcp`
