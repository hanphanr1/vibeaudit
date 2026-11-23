import { rules } from './rules';
import { categories, severities, type Audit, type Severity } from './types';
export type Threshold = Severity | 'none';
export const thresholds: readonly Threshold[] = [...severities,'none'];

export function toSarif(audit: Audit) {
  const indices = new Map(rules.map(({ruleId},index) => [ruleId,index]));
  return { $schema:'https://json.schemastore.org/sarif-2.1.0.json',version:'2.1.0',runs:[{
    tool:{driver:{name:'VibeAudit',informationUri:'https://github.com/hanphanr1/vibeaudit',rules:rules.map(rule => ({ id:rule.ruleId,name:rule.title,shortDescription:{text:rule.title},fullDescription:{text:rule.description},properties:{tags:[rule.cwe,rule.owasp,rule.category]} }))}},
    results:audit.findings.map(f => ({ ruleId:f.ruleId,ruleIndex:indices.get(f.ruleId),level:f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',message:{text:f.whyItMatters},locations:[{physicalLocation:{artifactLocation:{uri:f.file.split('/').map(encodeURIComponent).join('/')},region:{startLine:f.line,snippet:{text:f.snippet}}}}],partialFingerprints:{vibeauditFindingId:f.id} })),
    invocations:[{executionSuccessful:audit.coverage.complete,toolExecutionNotifications:audit.warnings.map(text => ({level:'warning',message:{text}}))}],
  }] };
}

export function toMarkdown(audit: Audit): string {
  const fence = '~~~';
  const block = (s: string) => fence + 'text\n' + s.replace(/^\s*~/gm,' ~\u200b') + '\n' + fence;
  const lines = ['# VibeAudit report','', '**Ship-readiness:** ' + audit.score + '/100 (' + audit.grade + ')','',audit.filesScanned + ' files analyzed.','', ...categories.map(category => '- ' + category + ': ' + audit.pillars[category] + '/100')];
  for (const warning of audit.warnings) lines.push('', '> ' + warning);
  for (const finding of audit.findings) lines.push('', '## ' + finding.title, '', finding.severity.toUpperCase() + ' · ' + finding.cwe + ' · ' + finding.owasp,'',block(finding.file + ':' + finding.line + '\n' + finding.snippet),'',finding.whyItMatters,'','### Suggested repair','',block(finding.patchDiff),'','### Regression check','',block(finding.testSuggestion));
  return lines.join('\n') + '\n';
}

export function ciWorkflow(threshold: Threshold): string {
  if (!thresholds.includes(threshold)) throw new Error('Invalid threshold.');
  return [
    'name: VibeAudit', 'on: [push, pull_request]', 'permissions:', '  contents: read', 'jobs:', '  audit:', '    runs-on: ubuntu-latest', '    steps:',
    '      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4', '        with: { persist-credentials: false }',
    '      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4', "        with: { node-version: '20' }",
    '      - name: Require a pinned scanner commit', '        env:',
    "          SCANNER_SHA: '<PINNED_COMMIT_SHA>' # Replace with a reviewed 40-character commit SHA.",
    '        run: |', '          if [[ ! "$SCANNER_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then',
    "            echo 'Pin VibeAudit to a reviewed 40-character commit SHA.' >&2", '            exit 1', '          fi',
    '          echo "VIBEAUDIT_SHA=$SCANNER_SHA" >> "$GITHUB_ENV"',
    '      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4',
    '        with:', '          repository: hanphanr1/vibeaudit', '          ref: ${{ env.VIBEAUDIT_SHA }}', '          path: .vibeaudit-tool', '          persist-credentials: false',
    '      - name: Build pinned scanner revision', '        run: |',
    '          npm ci --prefix .vibeaudit-tool --ignore-scripts', '          npm run build:tools --prefix .vibeaudit-tool',
    '      - name: Audit repository', '        run: node .vibeaudit-tool/bin/vibeaudit.cjs scan . --exclude .vibeaudit-tool --sarif --fail-on ' + threshold + ' > vibeaudit.sarif',
    '      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4',
    "        if: ${{ !cancelled() && hashFiles('vibeaudit.sarif') != '' }}", '        with: { name: vibeaudit-sarif, path: vibeaudit.sarif }', '',
  ].join('\n');
}
