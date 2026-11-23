import { scanTarget } from '../../../engine';
import { invalidGitHubTarget, isGitHubUrl } from '../../../engine/github-target';
import { presets, scanPreset, type Preset } from '../../../engine/presets';
import { guarded, InputError } from '../../../server/http';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const POST = guarded(async (body) => {
  if (!body || typeof body !== 'object' || !('kind' in body)) throw new InputError('Choose a target.');
  if (body.kind === 'benchmark') {
    const results = await Promise.all(presets.map(preset => scanPreset(preset)));
    return { results };
  }
  if (body.kind === 'preset' && 'preset' in body && presets.includes(body.preset as Preset)) return { audit: await scanPreset(body.preset as Preset) };
  if ((body.kind === 'local' || body.kind === 'github') && 'target' in body && typeof body.target === 'string') {
    const target = body.target.trim();
    if (!target || target.length > 4096 || /[\x00-\x1F]/.test(target)) throw new InputError('Enter a valid target.');
    if (body.kind === 'github' && !isGitHubUrl(target)) throw new InputError(invalidGitHubTarget);
    if (body.kind === 'local' && (/^[a-z][\w+.-]*:\/\//i.test(target) || target.startsWith('git@'))) throw new InputError('Enter a local folder, or switch to Public GitHub.');
    return { audit: await scanTarget(target) };
  }
  throw new InputError('Choose a local folder, public GitHub repository, or a demo.');
});

export { POST as DELETE, POST as GET, POST as HEAD, POST as OPTIONS, POST as PATCH, POST as PUT };
