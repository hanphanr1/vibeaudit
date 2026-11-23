import { access, readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { expect, test } from 'vitest';
import { runBoundedFetch, withPublicCheckout } from '../src/engine/checkout';

const entry = (size: number | string, path: string, mode = '100644') => `${mode} blob ${'a'.repeat(40)} ${size}\t${path}\0`;

test.each([entry(1024*1024 + 1,'large.ts'),entry('-', 'missing.ts'),Array.from({length:2_001},(_,i) => entry(0,'src/' + i + '.ts')).join(''),Array.from({length:51},(_,i) => entry(1024*1024,'src/' + i + '.ts')).join('')])('rejects oversized or uninspectable trees before checkout, then removes temp', async tree => {
  let temp = '';
  const commands: string[][] = [];
  await expect(withPublicCheckout('https://github.com/octocat/Hello-World', async (cwd,args) => {
    commands.push(args);
    if (args[0] === 'clone') { temp = cwd; return ''; }
    return tree;
  }, async () => { throw new Error('Must not scan'); })).rejects.toThrow(/budget|inspect/i);
  expect(commands[0]).toEqual(expect.arrayContaining(['--filter=blob:limit=1m','--no-checkout']));
  expect(commands.map(args => args[0])).toEqual(['clone','ls-tree']);
  await expect(access(temp)).rejects.toMatchObject({code:'ENOENT'});
});

test('checkout receives only reviewed regular paths and always cleans up', async () => {
  let temp = '';
  const commands: string[][] = [];
  await expect(withPublicCheckout('https://github.com/octocat/Hello-World', async (cwd,args) => {
    commands.push(args);
    if (args[0] === 'clone') { temp = cwd; return ''; }
    if (args[0] === 'ls-tree') return entry(10,'app.ts') + entry(4,'outside','120000');
    expect(args).toContain('--pathspec-file-nul');
    const manifest = args.find(arg => arg.startsWith('--pathspec-from-file='))!.split('=',2)[1];
    expect(await readFile(manifest,'utf8')).toBe('app.ts\0');
    return '';
  }, async (_root, omitted) => { expect(omitted).toEqual(['outside']); return 42; })).resolves.toBe(42);
  expect(commands.map(args => args[0] === '--literal-pathspecs' ? args[1] : args[0])).toEqual(['clone','ls-tree','checkout']);
  await expect(access(temp)).rejects.toMatchObject({code:'ENOENT'});
});

test('a live fetch exceeds its staging budget, is stopped before inspection, and leaves no temp directory', async () => {
  let temp = '';
  let child: ChildProcess | undefined;
  await expect(withPublicCheckout('https://github.com/octocat/Hello-World',async (cwd,args) => {
    if (args[0] !== 'clone') throw new Error('Must not inspect');
    temp = cwd;
    await runBoundedFetch(cwd, () => {
      child = spawn(process.execPath,['-e','require("node:fs").writeFileSync("synthetic.pack", Buffer.alloc(4096)); process.stdin.resume();'],{cwd,stdio:['pipe','ignore','ignore'],shell:false});
      return child;
    }, {bytes:1024,intervalMs:10,timeoutMs:2000});
    return '';
  }, async () => { throw new Error('Must not scan'); })).rejects.toThrow(/staging.*budget/i);
  expect(child && (child.exitCode !== null || child.signalCode !== null)).toBe(true);
  await expect(access(temp)).rejects.toMatchObject({code:'ENOENT'});
});
