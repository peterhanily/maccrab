Hunt for threats on this machine using MacCrab.

Use the maccrab MCP server `hunt` tool to search for: $ARGUMENTS

If no query was provided, ask the user what to search for. Example queries:
- "unsigned processes with network connections"
- "processes connecting to unusual ports"
- "files created in /tmp by non-system processes"
- "credential access attempts"
- "curl or wget downloads"

After getting results, analyze them:
- Flag anything suspicious with an explanation of why
- Note any processes that are unsigned or ad-hoc signed
- Highlight connections to unusual ports or IPs
- Suggest follow-up queries if the results are interesting

If no results are found, suggest alternative search terms.
