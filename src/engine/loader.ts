import { constants } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, sep } from 'node:path';
import { TextDecoder } from 'node:util';
import { maxBytes, maxFileBytes, maxFiles, runCheckoutGit, withPublicCheckout } from './checkout';
import { isGitHubUrl } from './github-target';

export interface SourceFile { path: string; text: string }
export interface LoadedTarget { files: SourceFile[]; trackedEnv: string[]; skippedAssets: number; incompleteReasons: string[] }
const ignored: Record<string, true> = Object.assign(Object.create(null), { node_modules:true, '.next':true, '.git':true, dist:true, build:true, notes:true });
const text = new TextDecoder('utf-8', { fatal: true });
async function walk(root: string, excludes: readonly string[]): Promise<LoadedTarget> {
  const files: SourceFile[] = [];
  const reasons = new Map<string, number>();
  const incomplete = (reason: string) => reasons.set(reason,(reasons.get(reason) ?? 0) + 1);
  let trackedEnv: string[] = [];
  let bytes = 0, entries = 0, skippedAssets = 0;
  const dirs = [''];
  const seen = new Set<string>();
  const isOutside = (path: string) => isAbsolute(path) || path === '..' || path.startsWith('..' + sep);
  const binaryAsset = /\.(?:png|ico|jpe?g|gif|webp|avif|bmp|woff2?|ttf|otf|pdf|mp[34]|mov|zip|gz|tar|7z)$/i;
  traversal: while (dirs.length) {
    const parent = dirs.pop()!;
    const dir = await opendir(join(root, parent)).catch(() => undefined);
    if (!dir) { if (!parent) throw new Error('Directory is not readable.'); incomplete('Source directories could not be read'); continue; }
    for await (const entry of dir) {
      if (++entries > 20_000) { incomplete('Directory entry budget exceeded'); break traversal; }
      const rel = parent ? parent + '/' + entry.name : entry.name;
      if (ignored[entry.name] || excludes.some(x => rel === x || rel.startsWith(x + '/'))) { skippedAssets++; continue; }
      const path = join(root, rel);
      if (entry.isSymbolicLink()) {
        const linked = await realpath(path).catch(() => undefined);
        if (!linked || isOutside(relative(root,linked))) incomplete('Outside-root or unresolved links were skipped');
        else incomplete('Symbolic source links were not analyzed');
        continue;
      }
      if (!entry.isDirectory() && (/^\.env(?:\.|$)/i.test(entry.name) || binaryAsset.test(entry.name))) { skippedAssets++; continue; }
      const actual = await realpath(path).catch(() => undefined);
      if (!actual) { incomplete('Source paths could not be resolved'); continue; }
      const fromRoot = relative(root,actual);
      if (isOutside(fromRoot)) { incomplete('Outside-root or unresolved links were skipped'); continue; }
      if (!fromRoot || seen.has(actual)) { incomplete('Repeated source paths were skipped'); continue; }
      seen.add(actual);
      if (entry.isDirectory()) { dirs.push(rel); continue; }
      if (!entry.isFile()) { incomplete('Non-regular source paths were skipped'); continue; }
      const metadata = await lstat(actual).catch(() => undefined);
      if (!metadata?.isFile()) { incomplete('Source files could not be read'); continue; }
      if (metadata.size > maxFileBytes) { incomplete('Per-file byte budget exceeded'); continue; }
      if (files.length >= maxFiles || metadata.size > maxBytes - bytes) { incomplete('Aggregate file or byte budget exceeded'); break traversal; }
      const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)).catch(() => undefined);
      if (!handle) { incomplete('Source files could not be opened'); continue; }
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.dev !== metadata.dev || stat.ino !== metadata.ino || stat.size !== metadata.size) { incomplete('Source files changed during the scan'); continue; }
        const buffer = Buffer.allocUnsafe(stat.size);
        let read = 0;
        while (read < buffer.length) {
          const chunk = await handle.read(buffer, read, buffer.length - read, read);
          if (!chunk.bytesRead) break;
          read += chunk.bytesRead;
        }
        bytes += read;
        const sample = buffer.subarray(0, read);
        if (read !== buffer.length || (await handle.stat()).size !== stat.size) { incomplete('Source files changed during the scan'); continue; }
        if (sample.includes(0)) { incomplete('Source files contained non-text data'); continue; }
        try { files.push({ path: rel, text: text.decode(sample) }); } catch { incomplete('Source files contained invalid UTF-8'); }
      } catch { incomplete('Source files could not be read'); }
      finally { await handle.close(); }
    }
  }
  const metadata = await lstat(join(root, '.git')).catch(error => {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') incomplete('Git metadata could not be read');
  });
  if (metadata?.isDirectory() || metadata?.isFile()) {
    try {
      const stdout = await runCheckoutGit(root, ['ls-files', '-z', '--', ':(glob)**/.env*']);
      trackedEnv = stdout.split('\0').filter(path => path && /^\.env(?:\.(?!example$|sample$|template$)[\w.-]+)?$/i.test(path.split('/').at(-1)!) && !excludes.some(x => path === x || path.startsWith(x + '/'))).sort();
    } catch { incomplete('Tracked dotenv inventory not available'); }
  }
  files.sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const incompleteReasons = [...reasons].map(([reason,count]) => reason + ' (' + count + ').');
  return { files, trackedEnv, skippedAssets, incompleteReasons };
}

export async function loadTarget(target: string, excludes: readonly string[] = []): Promise<LoadedTarget> {
  if (isGitHubUrl(target)) return withPublicCheckout(target,runCheckoutGit,async (checkout,omitted) => {
    const result = await walk(await realpath(checkout),excludes);
    if (omitted.length) result.incompleteReasons.push('Partial GitHub checkout: ' + omitted.length + ' symlink, submodule, or unsupported paths omitted.');
    return result;
  });
  if (/^[a-z][a-z+.-]*:\/\//i.test(target) || target.startsWith('git@')) throw new Error('Only public GitHub HTTPS repository URLs are supported.');
  if (/^[\\/]{2}/.test(target)) throw new Error('Network paths are not supported.');
  try {
    const actual = await realpath(target);
    if (/^[\\/]{2}/.test(actual)) throw new Error('Remote directory');
    return await walk(actual, excludes);
  } catch { throw new Error('Local directory is missing or unreadable.'); }
}
