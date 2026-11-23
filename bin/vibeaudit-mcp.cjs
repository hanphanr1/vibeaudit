#!/usr/bin/env node
const { startStdio } = require('../dist/tools/mcp.js');
startStdio().catch(() => { console.error('VibeAudit stdio transport failed.'); process.exitCode = 1; });
