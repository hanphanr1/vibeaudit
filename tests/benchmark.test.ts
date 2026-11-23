import { expect, test } from 'vitest';
import { rules, scanTarget } from '../src/engine';

test('vulnerable fixture covers all source rules except separately verified Git and lifecycle rules', async () => {
  const result = await scanTarget('fixtures/vulnerable-vibe-app');
  const separate = ['secret-tracked-env','config-install-pipe','config-install-encoded'];
  expect(new Set(result.findings.map(f => f.ruleId))).toEqual(new Set(rules.filter(r => !separate.includes(r.ruleId)).map(r => r.ruleId)));
  expect(JSON.stringify(result)).not.toContain('sk_live_FAKEdemo0000000001');
});

test('hardened near misses and clean self-scan have no findings', async () => {
  const runs = await Promise.all([scanTarget('fixtures/hardened-near-miss-app'),scanTarget('.', { exclude:['fixtures','tests'] })]);
  for (const run of runs) expect(run).toMatchObject({findings:[],score:100,grade:'A+',coverage:{complete:true,incompleteReasons:[]}});
});
