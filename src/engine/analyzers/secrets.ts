import { parse } from '@babel/parser';
import type { SourceFile } from '../loader';
import type { Hit } from '../types';

const patterns = [
  ['secret-supabase-secret', /\bsb_secret_[\da-zA-Z_-]{12,}/g],
  ['secret-stripe', /\b(?:sk|rk)_live_[\da-zA-Z]{16,}\b/g],
  ['secret-openai', /\bsk-(?!ant-)(?:proj-|svcacct-)?[\da-zA-Z_-]{24,}\b/g],
  ['secret-anthropic', /\bsk-ant-[\da-zA-Z_-]{24,}\b/g],
  ['secret-aws', /\bAKIA[A-Z0-9]{16}\b/g],
  ['secret-github', /\b(?:gh[pousr]_[\da-zA-Z]{30,}|github_pat_[\da-zA-Z_]{40,})\b/g],
  ['secret-resend', /\bre_[\da-zA-Z_]{24,}\b/g],
  ['secret-slack', /\bxox[baprs]-[\da-zA-Z-]{18,}\b/g],
  ['secret-twilio', /\bSK[0-9a-fA-F]{32}\b/g],
  ['secret-pem', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g],
] as const;
const jwt = /\beyJ[\da-zA-Z_-]*\.[\da-zA-Z_-]+\.[\da-zA-Z_-]+\b/g;
const publicKey = /\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|PRIVATE_KEY|SECRET|API_KEY|TOKEN|PASSWORD)[A-Z0-9_]*\b/g;
const publicAssignment = new RegExp(publicKey.source + String.raw`['"]?\s*[:=]\s*(?:(?:\/\*[\s\S]*?\*\/|\/\/[^\r\n]*)\s*)*(?:(['\x22\x60])((?:\\[\s\S]|(?!\1)[\s\S])*?)\1|([^\s;,})'"\x60]+))`, 'dg');
const weak = /\bprocess\.env\.([A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*(['"])(secret|password|changeme|dev-secret|123456|test)\2/gi;
const assignedSecret = /\b[\w$]*(?:SECRET|TOKEN|API_KEY|PASSWORD|SERVICE_ROLE_KEY)[\w$]*\s*[:=]\s*(['"`])(?:\\[\s\S]|(?!\1)[\s\S])*?\1/gi;
const sourcePatterns = [...patterns.map(([,regex]) => regex), jwt, weak, assignedSecret];
const maskedFiles = new WeakMap<SourceFile, { text: string; hidden: Set<number>; starts: number[]; withheld: boolean }>();

type Span = { start: number; end: number };
type Ast = { type: string; start?: number | null; end?: number | null; [key: string]: unknown };
const scriptFile = /\.[cm]?[jt]sx?$/i;
const publicName = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|PRIVATE_KEY|SECRET|API_KEY|TOKEN|PASSWORD)[A-Z0-9_]*$/;
const credentialIndicator = /(?:(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|PRIVATE_KEY|SECRET|API_KEY|TOKEN|PASSWORD)|[A-Za-z_$][\w$]*(?:SERVICE_ROLE_KEY|PRIVATE_KEY|SECRET|TOKEN|API_KEY|PASSWORD)[\w$]*)/;

function lineOf(starts: readonly number[], offset: number): number {
  let low = 0, high = starts.length;
  while (low + 1 < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

function child(node: Ast | undefined, key: string): Ast | undefined {
  const value = node?.[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Ast : undefined;
}

function walk(node: Ast | undefined, fn: (node: Ast) => void) {
  if (!node || typeof node.type !== 'string') return;
  fn(node);
  for (const [key,value] of Object.entries(node)) {
    if (key === 'loc' || key === 'extra' || key.endsWith('Comments')) continue;
    for (const item of Array.isArray(value) ? value : [value]) if (item && typeof item === 'object') walk(item as Ast, fn);
  }
}

function literalSpan(node: Ast | undefined): Span | undefined {
  if (node?.type === 'ParenthesizedExpression' || node?.type === 'TSAsExpression' || node?.type === 'TSSatisfiesExpression' || node?.type === 'TSNonNullExpression') return literalSpan(child(node,'expression'));
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') return undefined;
  if (node.type !== 'StringLiteral' && node.type !== 'TemplateLiteral') return undefined;
  return node.end - node.start >= 2 ? { start: node.start + 1, end: node.end - 1 } : undefined;
}

function literalSpans(node: Ast | undefined, out: Span[]): boolean {
  const span = literalSpan(node);
  if (span) { out.push(span); return true; }
  if (node?.type === 'BinaryExpression' && node.operator === '+') return literalSpans(child(node,'left'),out) && literalSpans(child(node,'right'),out);
  return false;
}

function keyOf(node: Ast | undefined): string {
  if (node?.type === 'Identifier') return typeof node.name === 'string' ? node.name : '';
  return node?.type === 'StringLiteral' && typeof node.value === 'string' ? node.value : '';
}

function targetOf(node: Ast): { name: string; value: Ast | undefined } | undefined {
  const left = child(node,'left');
  const id = child(node,'id');
  if (node.type === 'VariableDeclarator') return id?.type === 'Identifier' ? { name:keyOf(id), value:child(node,'init') } : undefined;
  if (node.type === 'AssignmentPattern') return left?.type === 'Identifier' ? { name:keyOf(left), value:child(node,'right') } : undefined;
  if (node.type === 'AssignmentExpression') {
    if (node.operator !== '=') return undefined;
    const name = left?.type === 'Identifier' ? keyOf(left) : left?.type === 'MemberExpression' || left?.type === 'OptionalMemberExpression' ? keyOf(child(left,'property')) : '';
    return { name, value:child(node,'right') };
  }
  if (node.type === 'ObjectProperty' || node.type === 'ClassProperty' || node.type === 'PropertyDefinition' || node.type === 'ClassAccessorProperty') return { name:keyOf(child(node,'key')), value:child(node,'value') };
  return undefined;
}

function publicLiteralSpans(file: SourceFile, text: string, starts: readonly number[], hidden: Set<number>): { spans: Span[]; withheld: boolean } {
  if (!scriptFile.test(file.path)) return { spans: [], withheld: false };
  const typescript = /\.[cm]?tsx?$/i.test(file.path);
  let program: Ast;
  try { program = parse(text,{ sourceType:'unambiguous', plugins: [...(typescript ? ['typescript' as const] : []), ...(!typescript || /tsx$/i.test(file.path) ? ['jsx' as const] : [])] }).program as unknown as Ast; }
  catch { return { spans: [], withheld: credentialIndicator.test(text) }; }
  const spans: Span[] = [];
  walk(program, node => {
    const target = targetOf(node);
    if (!target || !target.value || !publicName.test(target.name)) return;
    const { value } = target;
    const literals: Span[] = [];
    if (!literalSpans(value,literals) && typeof value.start === 'number' && typeof value.end === 'number') {
      for (let line = lineOf(starts,value.start); line <= lineOf(starts,value.end - 1); line++) hidden.add(line);
    }
    spans.push(...literals);
  });
  return { spans, withheld: false };
}

function maskSource(file: SourceFile) {
  const cached = maskedFiles.get(file);
  if (cached) return cached;
  const { text } = file;
  const spans: Span[] = [];
  for (const pattern of sourcePatterns) {
    for (const match of text.matchAll(pattern)) {
      spans.push({start:match.index,end:match.index + match[0].length});
    }
  }
  for (const match of text.matchAll(publicAssignment)) {
    const [start,end] = (match.indices?.[2] ?? match.indices?.[3])!;
    spans.push({start,end});
  }
  const hidden = new Set<number>();
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n',i + 1)) starts.push(i + 1);
  const script = publicLiteralSpans(file,text,starts,hidden);
  spans.push(...script.spans);
  spans.sort((a,b) => a.start - b.start);
  const chunks: string[] = [];
  let offset = 0, cursor = 0;
  for (const {start,end} of spans) {
    const firstBreak = text.indexOf('\n',start);
    if (firstBreak >= 0 && firstBreak < end) {
      while (cursor + 1 < starts.length && starts[cursor + 1] <= start) cursor++;
      for (let i = cursor; i < starts.length && starts[i] < end; i++) hidden.add(i + 1);
    }
    if (end <= offset) continue;
    if (start > offset) chunks.push(text.slice(offset,start));
    chunks.push(text.slice(Math.max(start,offset),end).replace(/[^\r\n]/g,'*'));
    offset = end;
  }
  chunks.push(text.slice(offset));
  const masked = {text:chunks.join(''),hidden,starts,withheld:script.withheld};
  maskedFiles.set(file,masked);
  return masked;
}

export function redact(text: string): string {
  text = text.replace(publicAssignment, (match, quote: string | undefined, quoted: string | undefined, bare: string | undefined) => {
    const value = quoted ?? bare ?? '';
    const tail = quote ?? '';
    return match.slice(0,match.length - value.length - tail.length) + '[REDACTED]' + (value.match(/\r?\n/g)?.join('') ?? '') + tail;
  });
  for (const [id, regex] of patterns) text = text.replace(regex, token => id === 'secret-pem' ? '[PRIVATE KEY REDACTED]' : token.slice(0, 5) + '****' + token.slice(-4));
  return text.replace(jwt, 'eyJ….[JWT REDACTED]').replace(weak, (_, name: string) => 'process.env.' + name + ' ?? "[REDACTED]"').replace(/((?:SECRET|TOKEN|API_KEY|PASSWORD|SERVICE_ROLE_KEY)\s*[:=]\s*)(['"])[^'"\r\n]+\2/gi, '$1"[REDACTED]"');
}

export function sourceHit(file: SourceFile, ruleId: string, offset: number, patch: string, test: string, snippet?: string): Hit {
  const masked = maskSource(file);
  const line = lineOf(masked.starts,offset);
  if (masked.withheld) return { ruleId,path:file.path,line,snippet:'[Source excerpt withheld: unparseable credential-bearing file]',patch,test };
  if (masked.hidden.has(line)) return { ruleId,path:file.path,line,snippet:'[Multiline credential context redacted]',patch:'Remove the embedded credential and load it from trusted server configuration. Rotate exposed credentials.',test:'Verify no credential material remains in source or the generated client bundle.' };
  return { ruleId,path:file.path,line,snippet:snippet ?? masked.text.slice(masked.starts[line - 1],masked.starts[line]).trim(),patch,test };
}

function assignment(text: string, offset: number): string | undefined {
  const before = text.slice(Math.max(text.lastIndexOf('\n', offset) + 1, offset - 150), offset);
  return /\b([A-Za-z_$][\w$]*)\s*[:=]\s*['"]?$/.exec(before)?.[1];
}

export function analyzeSecrets(file: SourceFile): Hit[] {
  const hits: Hit[] = [];
  const credential = (ruleId: string, offset: number, snippet?: string) => {
    const name = assignment(file.text, offset);
    const env = name && /^[A-Z][A-Z0-9_]+$/.test(name) && !/^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)/.test(name) ? name : 'SERVER_CREDENTIAL';
    hits.push(sourceHit(file, ruleId, offset, 'const ' + (name ?? 'credential') + ' = process.env.' + env + ';\nif (!' + (name ?? 'credential') + ') throw new Error("Missing server credential");', 'expect(process.env.' + env + ').toBeDefined(); // Configure a disposable value in test setup.', snippet));
  };
  for (const [id, regex] of patterns) for (const match of file.text.matchAll(regex)) credential(id, match.index, id === 'secret-pem' ? '[PRIVATE KEY REDACTED]' : undefined);
  for (const match of file.text.matchAll(jwt)) {
    try {
      const [,payload] = match[0].split('.');
      if (JSON.parse(Buffer.from(payload,'base64url').toString()).role === 'service_role') credential('secret-supabase-role', match.index);
    } catch { /* not a role-bearing JWT */ }
  }
  for (const match of file.text.matchAll(publicKey)) {
    const [name] = match;
    hits.push(sourceHit(file, 'secret-prefixed', match.index, '- ' + name + '\n+ ' + name.replace(/^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)/, ''), 'expect(clientEnvironmentKeys).not.toContain(' + JSON.stringify(name) + ');', name + ' = [REDACTED]'));
  }
  for (const match of file.text.matchAll(weak)) {
    const name = match[1];
    hits.push(sourceHit(file, 'secret-weak-fallback', match.index, 'const credential = process.env.' + name + ';\nif (!credential) throw new Error("Missing ' + name + '");', 'expect(() => readCredential({})).toThrow();'));
  }
  return hits;
}
