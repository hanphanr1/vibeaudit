import { rules, scanTarget } from '../engine';
import { thresholds, toMarkdown, toSarif, type Threshold } from '../engine/exporters';
import { severities } from '../engine/types';

const usage = 'Usage: vibeaudit rules | vibeaudit scan <path-or-github-url> [--json|--sarif|--md] [--fail-on critical|high|medium|low|none] [--exclude path]';

export async function runCli(args: string[], stdout = console.log, stderr = console.error): Promise<number> {
  if (args.length === 1 && args[0] === 'rules') {
    for (const rule of rules) stdout([rule.ruleId,rule.severity,rule.cwe,rule.title].join('\t'));
    return 0;
  }
  if (args.length === 1 && ['-h','--help'].includes(args[0])) { stdout(usage); return 0; }
  let format: string | undefined, threshold: Threshold | undefined;
  const exclude: string[] = [];
  const [, target] = args;
  if (args[0] !== 'scan' || !target || target.startsWith('-')) { stderr(usage); return 2; }
  for (let i = 2; i < args.length; i++) {
    const key = args[i];
    if (['--json','--sarif','--md'].includes(key) && !format) format = key;
    else if (key === '--fail-on' && !threshold) {
      const value = args[++i] as Threshold;
      if (!thresholds.includes(value)) { stderr(usage); return 2; }
      threshold = value;
    } else if (key === '--exclude') {
      const value = args[++i]?.replaceAll('\\','/');
      if (!value || !/^[\w.-]+(?:\/[\w.-]+)*$/.test(value) || value.split('/').some(part => part === '.' || part === '..')) { stderr(usage); return 2; }
      exclude.push(value);
    } else { stderr(usage); return 2; }
  }
  try {
    const audit = await scanTarget(target,{exclude});
    if (format === '--json') stdout(JSON.stringify(audit,null,2));
    else if (format === '--sarif') stdout(JSON.stringify(toSarif(audit),null,2));
    else if (format === '--md') stdout(toMarkdown(audit));
    else {
      stdout('Ship-readiness: ' + audit.score + '/100 (' + audit.grade + ') · ' + audit.findings.length + ' findings · ' + audit.filesScanned + ' files');
      for (const f of audit.findings) stdout(f.severity.toUpperCase() + ' ' + f.ruleId + ' ' + f.file + ':' + f.line + ' ' + f.title);
    }
    const cutoff = threshold ?? 'none';
    if (!audit.coverage.complete) {
      for (const reason of audit.coverage.incompleteReasons) stderr('Incomplete scan: ' + reason);
      if (cutoff !== 'none') return 1;
    }
    return cutoff !== 'none' && severities.slice(0,severities.indexOf(cutoff) + 1).some(level => audit.counts[level] > 0) ? 1 : 0;
  } catch (error) { stderr(error instanceof Error ? error.message : 'Scan failed.'); return 2; }
}
