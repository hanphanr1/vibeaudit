import { afterEach, expect, test } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadTarget } from '../src/engine/loader';
import { isGitHubUrl } from '../src/engine/github-target';
import { scanTarget } from '../src/engine';

let temp: string | undefined;
afterEach(async () => { if (temp) await rm(temp, { recursive: true, force: true }); temp = undefined; });

test('only canonical public GitHub HTTPS repository URLs are accepted', () => {
  expect(isGitHubUrl('https://github.com/my-org/repo.one')).toBe(true);
  for (const url of ['https://github.com/-org/repo', 'https://github.com/org/..', 'https://github.com/org/repo?x=1', 'https://github.com:443/org/repo', 'https://github.com.evil.invalid/org/repo', 'https://github.com/org/%2erepo', 'https://github.com/user/repo/', 'git@github.com:org/repo']) expect(isGitHubUrl(url)).toBe(false);
});

test('outside links, binaries, oversized files and dependency trees are not read', async () => {
  temp = await mkdtemp(join(tmpdir(), 'vibeaudit-test-'));
  const root = join(temp, 'source');
  const outside = join(temp, 'outside');
  await mkdir(join(root, 'node_modules'), { recursive: true });
  await mkdir(outside);
  await writeFile(join(outside, 'private.ts'), 'outside');
  await symlink(outside, join(root, 'escape'), 'junction');
  await writeFile(join(root, 'app.ts'), 'export const hello = true;');
  await writeFile(join(root, 'node_modules', 'dependency.js'), 'ignored');
  await writeFile(join(root, 'binary.js'), Buffer.from([0, 0xff, 0]));
  await writeFile(join(root, 'large.txt'), Buffer.alloc(1024 * 1024 + 1, 65));
  await writeFile(join(root, 'asset.png'), Buffer.from([0, 0xff, 0]));
  const loaded = await loadTarget(root);
  expect(loaded.files.map(file => file.path)).toEqual(['app.ts']);
  expect(loaded.skippedAssets).toBe(2);
  expect(loaded.incompleteReasons).toEqual(expect.arrayContaining([expect.stringMatching(/outside-root/i),expect.stringMatching(/budget/i)]));
});

test('Git-tracked dotenv is flagged without reading tracked or untracked values', async () => {
  temp = await mkdtemp(join(tmpdir(), 'vibeaudit-git-test-'));
  execFileSync('git', ['init','-q',temp]);
  await writeFile(join(temp,'.env'),'TOKEN=synthetic-private-value');
  await writeFile(join(temp,'.env.local'),'TOKEN=another-private-value');
  execFileSync('git',['-C',temp,'add','--','.env']);
  const audit = await scanTarget(temp);
  expect(audit.findings.map(f => [f.ruleId,f.file])).toEqual([['secret-tracked-env','.env']]);
  expect(JSON.stringify(audit)).not.toContain('private-value');
});
