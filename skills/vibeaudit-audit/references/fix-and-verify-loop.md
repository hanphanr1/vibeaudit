# Fix and verify loop

From the trusted scanner checkout: `npm run cli -- scan /path/to/project --json --fail-on none`. MCP: call `vibeaudit_scan_path` with `{"path":"/path/to/project"}` and `vibeaudit_list_rules` with `{}`. Keep the target and exclusions unchanged on rescan.

1. Save the pre-fix findings and coverage warnings. For each proposed change, identify the exact access or data invariant it should preserve. When evidence is missing, label the issue unresolved rather than suppressing it.
2. Add a regression test that fails for the original behavior. Apply the smallest reviewed correction and run the focused test, then the project’s local test suite. Do not replay untrusted commands or use production credentials.
3. Run `npm run cli -- scan /path/to/project --fail-on high`. Exit 0 means the configured threshold was not reached; exit 1 blocks release, and exit 2 means no valid scan result. Resolve coverage gaps before treating a run as a release check.
4. Use `node bin/vibeaudit.cjs scan /path/to/project --sarif > report.sarif` and `node bin/vibeaudit.cjs scan /path/to/project --md > report.md` after `npm run build:tools`. Generate CI locally via `vibeaudit_generate_ci` with `{"threshold":"high"}`. Save the YAML to `.github/workflows/vibeaudit.yml` and pin its scanner checkout to a reviewed revision before enabling it.
