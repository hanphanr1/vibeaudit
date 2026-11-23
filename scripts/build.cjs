const { spawnSync } = require('node:child_process');
const build = spawnSync(process.execPath, [require.resolve('next/dist/bin/next'), 'build'], {
  stdio: 'inherit',
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' },
});
if (build.error) console.error(build.error.message);
process.exitCode = build.status ?? 1;
