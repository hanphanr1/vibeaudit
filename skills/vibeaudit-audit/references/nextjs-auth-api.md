# Next.js auth and APIs

From the trusted scanner checkout: `npm run cli -- scan /path/to/project --json --fail-on none`. MCP: call `vibeaudit_scan_path` with `{"path":"/path/to/project"}` and `vibeaudit_list_rules` with `{}`. Keep the target and exclusions unchanged on rescan.

1. Identify the exported handler or action that can mutate state. If it is a public identity entry point, read its own credential validation. For a private route, trace what happens when identity is absent before any write. A helper named like a guard is not evidence unless it rejects or its result is checked.
2. If authentication is present, check ownership or membership on each data write. For Supabase server code, prefer verified getUser() over trusting session contents. If redirect input is involved, require an explicit set of internal destinations.
3. Patch the actual handler with the project’s verified guard, then enforce resource-level authorization. Test unauthenticated denial, cross-owner denial, and a legitimate mutation using a disposable store. Confirm a denied request checkpoints no changes. Rescan and record any route the AST parser could not analyze.
