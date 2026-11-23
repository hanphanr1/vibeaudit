import { resolve } from 'node:path';
import { scanTarget } from './index';
export const presets = ['vulnerable','hardened','self'] as const;
export type Preset = typeof presets[number];
export const presetNames: Record<Preset, string> = { vulnerable:'Vulnerable Demo',hardened:'Hardened Near-Miss',self:'Self-Scan VibeAudit' };
export function scanPreset(preset: Preset, base = process.cwd()) {
  if (preset === 'self') return scanTarget(base,{ exclude:['fixtures','tests'] });
  return scanTarget(resolve(base,'fixtures',preset === 'vulnerable' ? 'vulnerable-vibe-app' : 'hardened-near-miss-app'));
}
