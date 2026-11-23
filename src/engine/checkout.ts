import { execFile, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { lstat, mkdtemp, opendir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const maxFileBytes = 1024 * 1024;
export const maxBytes = 50 * maxFileBytes;
export const maxFiles = 2_000;
const MAX_FETCH_BYTES = 50 * maxFileBytes;
const windows = process.platform === 'win32';
const gitTimeoutMs = 30_000;
const nullPath = windows ? 'NUL' : '/dev/null';

export async function runCheckoutGit(cwd: string, args: string[]): Promise<string> {
  const clone = args[0] === 'clone';
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TMP|TEMP|TMPDIR)$/i.test(key)));
  const env = { ...inherited, NODE_ENV: 'production', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: nullPath, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never', GIT_OPTIONAL_LOCKS: '0', GIT_NO_LAZY_FETCH: '1' } as const;
  const options = ['-c', 'core.hooksPath=' + nullPath, '-c', 'core.symlinks=false', '-c', 'core.fsmonitor=false', '-c', 'credential.helper=', '-c', 'http.followRedirects=false', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=' + (clone ? 'always' : 'never'), ...args];
  if (clone) {
    await runBoundedFetch(cwd, () => spawn('git',options,{cwd,env,shell:false,windowsHide:true,detached:!windows,stdio:'ignore'}), {processTree:true});
    return '';
  }
  return new Promise((resolve,reject) => execFile('git',options,{cwd,env,windowsHide:true,timeout:gitTimeoutMs,maxBuffer:4 * maxFileBytes},(error,stdout) => error ? reject(error) : resolve(stdout)));
}

async function exceedsBytes(dir: string, limit: number): Promise<boolean> {
  const pending = [dir];
  let bytes = 0;
  while (pending.length) {
    const root = pending.pop()!;
    const listing = await opendir(root).catch(error => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    });
    if (!listing) continue;
    for await (const entry of listing) {
      const path = join(root,entry.name);
      if (entry.isDirectory()) { pending.push(path); continue; }
      if (!entry.isFile()) continue;
      const stat = await lstat(path).catch(error => {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      });
      if (stat?.isFile() && (bytes += stat.size) > limit) return true;
    }
  }
  return false;
}

class FetchError extends Error {}
interface FetchLimits { bytes?: number; intervalMs?: number; timeoutMs?: number; processTree?: boolean }

export async function runBoundedFetch(root: string, launch: () => ChildProcess, limits: FetchLimits = {}): Promise<void> {
  const {bytes = MAX_FETCH_BYTES, intervalMs = 50, timeoutMs = gitTimeoutMs, processTree = false} = limits;
  const child = launch();
  let closed = false, failure: FetchError | undefined, stopping: Promise<void> | undefined, check: Promise<void> | undefined;
  const stop = (message: string) => {
    failure ??= new FetchError(message);
    if (closed || stopping || !child.pid) return;
    const pid = child.pid;
    if (processTree && windows) {
      stopping = new Promise<void>(resolve => {
        execFile(join(process.env.SystemRoot ?? 'C:\\Windows','System32','taskkill.exe'),['/PID',String(pid),'/T','/F'],{windowsHide:true,timeout:3000},() => { if (!closed) child.kill('SIGKILL'); resolve(); });
      });
    } else if (processTree) {
      try { process.kill(-pid,'SIGKILL'); } catch { child.kill('SIGKILL'); }
    } else child.kill('SIGKILL');
  };
  const budgetMessage = 'Public GitHub fetch exceeded the staging disk budget.';
  const monitor = setInterval(() => {
    if (closed || failure || check) return;
    check = exceedsBytes(root,bytes)
      .then(over => { if (over) stop(budgetMessage); }, () => stop('Could not verify the GitHub fetch staging budget.'))
      .finally(() => { check = undefined; });
  },intervalMs);
  const deadline = setTimeout(() => stop('Public GitHub fetch exceeded the time limit.'),timeoutMs);
  try {
    const code = await new Promise<number | null>(resolve => {
      child.once('error',() => stop('Could not start the public GitHub fetch.'));
      child.once('close',code => { closed = true; resolve(code); });
    });
    await check;
    await stopping;
    if (failure) throw failure;
    if (await exceedsBytes(root,bytes)) throw new FetchError(budgetMessage);
    if (code !== 0) throw new FetchError('Public GitHub fetch failed.');
  } finally { clearInterval(monitor); clearTimeout(deadline); }
}

export async function withPublicCheckout<T>(url: string, git: (cwd: string, args: string[]) => Promise<string>, audit: (root: string, omitted: string[]) => Promise<T>): Promise<T> {
  const temp = await mkdtemp(join(tmpdir(), 'vibeaudit-'));
  try {
    const root = join(temp, 'repository');
    await git(temp,['clone','--depth','1','--single-branch','--filter=blob:limit=1m','--no-checkout','--no-recurse-submodules','--',url,root]).catch(error => {
      if (error instanceof FetchError) throw error;
      throw new Error('Public GitHub fetch failed.');
    });
    const tree = await git(root,['ls-tree','-r','-l','-z','HEAD']).catch(() => { throw new Error('Could not inspect the GitHub tree within scan limits.'); });
    const paths: string[] = [], omitted: string[] = [];
    let bytes = 0, entries = 0;
    for (const entry of tree.split('\0')) {
      if (!entry) continue;
      const fields = /^(\d{6}) (blob|commit) [a-f\d]{40,64}\s+([\d-]+)\t([\s\S]+)$/.exec(entry);
      if (!fields) throw new Error('Could not inspect a public GitHub tree entry.');
      const [,mode,type,size,path] = fields;
      if (++entries > maxFiles) throw new Error('Public GitHub tree exceeds the file-count budget.');
      const parts = path.split('/');
      if (type !== 'blob' || !/^(100644|100755)$/.test(mode) || parts.some(part => !part || part === '.' || part === '..' || /^\.git$/i.test(part)) || /[\\\x00-\x1f]/.test(path) || (process.platform === 'win32' && (/[<>:"|?*]/.test(path) || parts.some(part => /[. ]$|^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))))) { omitted.push(path); continue; }
      const length = Number(size);
      if (!Number.isSafeInteger(length) || length < 0) throw new Error('Could not inspect a filtered GitHub blob size within the budget.');
      bytes += length;
      if (length > maxFileBytes || bytes > maxBytes) throw new Error('Public GitHub tree exceeds the blob-byte budget.');
      paths.push(path);
    }
    if (paths.length) {
      const manifest = join(temp,'checkout-paths');
      await writeFile(manifest,paths.join('\0') + '\0');
      await git(root,['--literal-pathspecs','checkout','HEAD','--pathspec-from-file=' + manifest,'--pathspec-file-nul'])
        .catch(() => { throw new Error('Could not check out the inspected GitHub files.'); });
    }
    return await audit(root,omitted);
  } finally { await rm(temp,{recursive:true,force:true,maxRetries:4,retryDelay:50}); }
}
