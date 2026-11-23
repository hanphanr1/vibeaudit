# Contributing

Install with `npm ci`. Run `npm test`, `npm run build`, and `node bin/vibeaudit.cjs scan . --exclude fixtures --exclude tests --fail-on low` before opening a change. Include a synthetic positive and a plausible near miss for each rule change. Never include real secrets, live probes, or executable attack examples. Verify suggested patches with the affected framework or SQL dialect.
