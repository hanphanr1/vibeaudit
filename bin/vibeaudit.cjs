#!/usr/bin/env node
const { runCli } = require('../dist/tools/cli.js');
runCli(process.argv.slice(2)).then(code => { process.exitCode = code; });
