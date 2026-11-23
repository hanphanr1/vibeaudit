'use client';
import { useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { categories, severities, type Audit, type Category, type Finding, type Rule, type Severity } from '../engine/types';
import type { Preset } from '../engine/presets';
import { ciWorkflow, thresholds, toMarkdown, toSarif, type Threshold } from '../engine/exporters';
import { invalidGitHubTarget, isGitHubUrl } from '../engine/github-target';

const tabs = ['Audit Scanner','Rules & Benchmark','CI & MCP Setup'] as const;
const demos: [Preset,string,string][] = [ ['vulnerable','Scan Vulnerable Demo','Vulnerable Demo'], ['hardened','Scan Hardened Near-Miss','Hardened Near-Miss'], ['self','Self-Scan VibeAudit','Self-Scan'] ];
const detailTabs = [['patchDiff','Tailored Patch / Diff'],['aiFixPrompt','Fix Prompt'],['testSuggestion','Regression Test']] as const;
const config = JSON.stringify({mcpServers:{vibeaudit:{command:'node',args:['/absolute/path/to/vibeaudit/bin/vibeaudit-mcp.cjs']}}},null,2);

function Icon({kind}:{kind:'shield'|'scan'|'list'|'terminal'|'copy'|'download'}) {
  const paths: Record<typeof kind, ReactNode> = {
    shield:<><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/><path d="m8.5 12 2.3 2.3 4.8-5"/></>,
    scan:<><path d="M9 3H3v6m12-6h6v6m0 6v6h-6m-6 0H3v-6M3 12h18"/></>,
    list:<><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/></>,
    terminal:<><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/></>,
    copy:<><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 4H5a1 1 0 0 0-1 1v11"/></>,
    download:<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>,
  };
  return <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round">{paths[kind]}</svg>;
}

async function runScan(body: object): Promise<{audit?:Audit;results?:Audit[]}> {
  const response = await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? 'Scan failed.');
  return payload;
}

function download(filename: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text],{type}));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url),500);
}

function Copy({ value, label }: { value: string; label: string }) {
  const [state,setState] = useState('');
  return <button type="button" className="tool-button" onClick={async () => {
    try { await navigator.clipboard.writeText(value); setState('Copied'); }
    catch { setState('Select text to copy'); }
  }}><Icon kind="copy"/>{label}<span aria-live="polite" className={state ? 'copy-state' : 'sr-only'}>{state}</span></button>;
}

function Score({audit}:{audit:Audit}) {
  return <div className="score-section panel">
    <div className="readiness"><span className="label">Ship-readiness</span><div className={'ring ' + (audit.score === 100 ? 'pass' : '')} role="img" aria-label={audit.score + ' out of 100, grade ' + audit.grade}>
      <svg viewBox="0 0 108 108" aria-hidden="true"><circle cx="54" cy="54" r="45" className="track"/><circle cx="54" cy="54" r="45" pathLength="100" strokeDasharray={audit.score + ' 100'} transform="rotate(-90 54 54)" className="meter"/></svg>
      <span><strong>{audit.score}</strong><small> / 100</small></span>
    </div><span className="grade">Grade {audit.grade}</span></div>
    <div className="pillars"><h2>Security pillars</h2>{categories.map(cat => <div className="pillar" key={cat}><label htmlFor={'pillar-'+cat}>{cat}</label><progress id={'pillar-'+cat} value={audit.pillars[cat]} max="100"/><output>{audit.pillars[cat]}</output></div>)}</div>
    <div className="verdict"><h2>Finding severity</h2><div className="severity-grid">{severities.map(level => <div key={level} className={'severity tone-' + level}><strong>{audit.counts[level]}</strong><span>{level}</span></div>)}</div>
      <label className="export-label">Export report<select value="" onChange={e => {
        if (e.target.value === 'md') download('vibeaudit.md',toMarkdown(audit),'text/markdown');
        if (e.target.value === 'sarif') download('vibeaudit.sarif',JSON.stringify(toSarif(audit),null,2),'application/sarif+json');
        if (e.target.value === 'json') download('vibeaudit.json',JSON.stringify(audit,null,2),'application/json');
      }}><option value="" disabled>Choose format</option><option value="md">Markdown</option><option value="sarif">SARIF</option><option value="json">JSON</option></select></label>
    </div>
  </div>;
}

function Inspector({finding}:{finding:Finding}) {
  const [detail,setDetail] = useState<typeof detailTabs[number][0]>('patchDiff');
  const copyLabel = detail === 'patchDiff' ? 'Copy patch' : detail === 'aiFixPrompt' ? 'Copy prompt' : 'Copy test';
  return <article className="inspector" aria-label="Finding Inspector">
    <div className="fact-line"><span className={'tag tone-' + finding.severity}>{finding.severity}</span><code>{finding.file}:{finding.line}</code></div>
    <h3>{finding.title}</h3><div className="fact-line"><span className="tag">{finding.cwe}</span><span className="tag">OWASP {finding.owasp}</span><span className="tag">{finding.category}</span></div>
    <p className="explanation">{finding.whyItMatters}</p>
    <h4>Code context</h4><pre className="code"><code>{finding.snippet}</code></pre>
    <div className="detail-tabs" aria-label="Remediation views">{detailTabs.map(([id,label]) => <button key={id} type="button" aria-pressed={detail === id} onClick={() => setDetail(id)}>{label}</button>)}</div>
    <pre className={'code ' + (detail === 'patchDiff' ? 'patch' : '')}><code>{finding[detail]}</code></pre><Copy key={detail} value={finding[detail]} label={copyLabel}/>
  </article>;
}

function Findings({audit}:{audit:Audit}) {
  const [query,setQuery] = useState('');
  const [severity,setSeverity] = useState<Severity | ''>('');
  const [category,setCategory] = useState<Category | ''>('');
  const [selected,setSelected] = useState('');
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return audit.findings.filter(f => (!severity || severity === f.severity) && (!category || category === f.category) && (f.title + ' ' + f.ruleId + ' ' + f.file).toLowerCase().includes(needle));
  },[audit,query,severity,category]);
  const finding = visible.find(f => f.id === selected) ?? visible[0];
  return <section className="panel evidence" aria-label="Findings explorer">
    <header><div><h2>Findings explorer</h2><p>{visible.length} of {audit.findings.length} findings · {audit.filesScanned} files analyzed</p></div></header>
    {audit.findings.length > 0 ? <><div className="filters"><input type="search" aria-label="Search findings" placeholder="Search title, rule or file" value={query} onChange={e => setQuery(e.target.value)}/><select aria-label="Severity filter" value={severity} onChange={e => setSeverity(e.target.value as Severity | '')}><option value="">All severities</option>{severities.map(s => <option key={s}>{s}</option>)}</select><select aria-label="Category filter" value={category} onChange={e => setCategory(e.target.value as Category | '')}><option value="">All categories</option>{categories.map(c => <option key={c}>{c}</option>)}</select></div>
    {finding ? <div className="workbench"><ul className="findings" aria-label="Matching findings">{visible.map(f => <li key={f.id}><button type="button" aria-pressed={f.id === finding.id} onClick={() => setSelected(f.id)}><span className={'tag tone-' + f.severity}>{f.severity}</span><strong>{f.title}</strong><code>{f.file}:{f.line}</code></button></li>)}</ul><Inspector key={finding.id} finding={finding}/></div> : <p className="empty">No findings match these filters.</p>}</> : <p className="empty passing">No findings in the analyzed files. Review scan warnings and runtime access separately.</p>}
  </section>;
}

function Rules({rules, results, pending, run}:{rules:Rule[];results:Audit[] | null;pending:boolean;run:()=>void}) {
  const [query,setQuery] = useState('');
  const needle = query.trim().toLowerCase();
  const visible = rules.filter(r => [r.title,r.ruleId,r.category,r.severity,r.cwe,r.description].some(v => v.toLowerCase().includes(needle)));
  return <>
    <section className="panel benchmark"><header><div><h2>Accuracy benchmark</h2><p>Run the same scanner against two synthetic fixtures and this repository.</p></div><button className="primary" onClick={run} disabled={pending}><Icon kind="scan"/>Run Accuracy Benchmark</button></header>
    {results ? <div className="benchmark-grid">{results.map((run,i) => <article key={demos[i][0]}><span className="label">{demos[i][2]}</span><strong className={run.score === 100 && run.coverage.complete ? 'passing' : ''}>{run.score}<small> / 100</small></strong><span>Grade {run.grade} · {run.findings.length} findings{!run.coverage.complete && ' · Incomplete coverage'}</span>{!run.coverage.complete && <p>{run.coverage.incompleteReasons.join(' ')}</p>}</article>)}</div> : <p className="empty">Run the benchmark to compare detections with the two clean controls.</p>}</section>
    <section className="panel rule-catalogue"><header><div><h2>Rule catalogue</h2><p>{visible.length} of {rules.length} deterministic rules</p></div><input type="search" aria-label="Search rules" placeholder="Search rules, category or CWE" value={query} onChange={e => setQuery(e.target.value)}/></header>
    {visible.length ? <ul>{visible.map(rule => <li key={rule.ruleId}><span className={'tag tone-' + rule.severity}>{rule.severity}</span><div><strong>{rule.title}</strong><p>{rule.description}</p><code>{rule.ruleId} · {rule.category} · {rule.cwe}</code></div></li>)}</ul> : <p className="empty">No rules match that search.</p>}</section>
  </>;
}

function Setup() {
  const [threshold,setThreshold] = useState<Threshold>('high');
  const yaml = ciWorkflow(threshold);
  return <div className="setup-grid"><section className="panel setup"><h2>GitHub Actions</h2><p>Save this workflow as <code>.github/workflows/vibeaudit.yml</code>.</p><label className="field">Fail on<select value={threshold} onChange={e => setThreshold(e.target.value as Threshold)}>{thresholds.map(t => <option key={t}>{t}</option>)}</select></label><pre className="code"><code>{yaml}</code></pre><div className="actions"><Copy key={threshold} value={yaml} label="Copy workflow"/><button className="tool-button" onClick={() => download('vibeaudit.yml',yaml,'text/yaml')}><Icon kind="download"/>Download workflow</button></div></section>
    <section className="panel setup"><h2>MCP server</h2><p>Build the tools, then add this configuration to a local stdio client. Replace the path with your checkout.</p><pre className="code"><code>{config}</code></pre><Copy value={config} label="Copy MCP config"/><h3>CLI quick commands</h3><pre className="code"><code>{'npm run build:tools\nnode bin/vibeaudit.cjs rules\nnode bin/vibeaudit.cjs scan . --fail-on high\nnode bin/vibeaudit.cjs scan . --sarif > vibeaudit.sarif'}</code></pre></section></div>;
}

export function Studio({rules}:{rules:Rule[]}) {
  const [tab,setTab] = useState<number>(0);
  const [kind,setKind] = useState<'local'|'github'>('local');
  const [target,setTarget] = useState('');
  const [pending,setPending] = useState(false);
  const [auditError,setAuditError] = useState('');
  const [benchmarkError,setBenchmarkError] = useState('');
  const [audit,setAudit] = useState<Audit | null>(null);
  const [results,setResults] = useState<Audit[] | null>(null);
  const [scanId,setScanId] = useState(0);
  const [label,setLabel] = useState('');
  async function scan(body: {kind:string; target?:string; preset?:Preset}, title: string) {
    const benchmark = body.kind === 'benchmark';
    const setError = benchmark ? setBenchmarkError : setAuditError;
    setPending(true); setError('');
    try {
      const data = await runScan(body);
      if (benchmark) {
        if (!Array.isArray(data.results) || data.results.length !== demos.length) throw new Error('Benchmark did not return results.');
        setResults(data.results);
      } else {
        if (!data.audit) throw new Error('Scan did not return results.');
        setAudit(data.audit); setLabel(title); setScanId(id => id + 1);
      }
    } catch (error) { setError(error instanceof Error ? error.message : 'Scan failed.'); }
    finally { setPending(false); }
  }
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = target.trim();
    if (pending || !trimmed) return;
    if (kind === 'github' && !isGitHubUrl(trimmed)) { setAuditError(invalidGitHubTarget); return; }
    void scan({kind,target:trimmed},trimmed);
  };
  return <>
    <header className="topbar"><div className="topbar-inner"><div className="brand"><span className="brand-icon"><Icon kind="shield"/></span><strong>VibeAudit</strong><span className="brand-separator">/</span><span>Security Studio</span></div><span className="local"><i/>Loopback only</span></div></header>
    <main>
      <div className="intro"><div className="eyeline"><span/>Source security</div><h1>VibeAudit Studio</h1><p>Review source risks, verify fixes, and gate the next release.</p></div>
      <nav className="nav" aria-label="Studio sections">{tabs.map((name,i) => <button key={name} type="button" aria-current={tab === i ? 'page' : undefined} onClick={() => setTab(i)}><Icon kind={(['scan','list','terminal'] as const)[i]}/>{name}</button>)}</nav>
      {pending && tab !== 2 && <p className="banner" role="status">Analyzing source files…</p>}
      {tab === 0 && <>
        {auditError && <p className="banner is-error" role="alert">{auditError}</p>}
        {auditError && audit && <p className="banner" role="status">Showing preserved results from the previous successful scan.</p>}
        <section className="panel target"><header><div><h2>Scan target</h2><p>Analyze files without running the project.</p></div><div className="segmented" aria-label="Target type"><button type="button" aria-pressed={kind === 'local'} onClick={() => setKind('local')}>Local Path</button><button type="button" aria-pressed={kind === 'github'} onClick={() => setKind('github')}>Public GitHub</button></div></header>
          <form onSubmit={submit}><input aria-label={kind === 'local' ? 'Local folder path' : 'Public GitHub repository URL'} value={target} onChange={e => setTarget(e.target.value)} placeholder={kind === 'local' ? './your-project' : 'https://github.com/owner/repo'} maxLength={4096} required/><button className="primary" disabled={pending || !target.trim()}><Icon kind="scan"/>Scan target</button></form>
          <div className="presets">{demos.map(([id,text]) => <button type="button" key={id} className="tool-button" disabled={pending} onClick={() => void scan({kind:'preset',preset:id},text)}>{text}</button>)}</div>
        </section>
        {audit ? <><div className="result-title"><h2>Scan results</h2><code>{label}</code></div><Score audit={audit}/>{audit.warnings.length > 0 && <ul className="warnings" aria-label="Scan warnings">{audit.warnings.map(w => <li key={w}>{w}</li>)}</ul>}<Findings key={scanId} audit={audit}/></> : <section className="panel ready"><Icon kind="scan"/><div><h2>No scan running</h2><p>Choose a directory, a public repository, or a built-in benchmark.</p></div></section>}
      </>}
      {tab === 1 && <>
        {benchmarkError && <p className="banner is-error" role="alert">{benchmarkError}</p>}
        {benchmarkError && results && <p className="banner" role="status">Showing preserved results from the previous successful benchmark.</p>}
        <Rules rules={rules} results={results} pending={pending} run={() => void scan({kind:'benchmark'},'Benchmark')}/>
      </>}
      {tab === 2 && <Setup/>}
      <footer><span>VibeAudit</span><span>Static analysis · Findings require context review</span></footer>
    </main>
  </>;
}
