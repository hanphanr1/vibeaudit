import { expect, test } from 'vitest';
import { auditFiles } from '../src/engine';
import { toSarif } from '../src/engine/exporters';
import { redact } from '../src/engine/analyzers/secrets';

function jwt(role: string) {
  return ['eyJhbGciOiJIUzI1NiJ9', Buffer.from(JSON.stringify({ role })).toString('base64url'), 'syntheticsignature000000000000000000000000'].join('.');
}
const file = (path: string, text: string) => ({ path, text });
const ids = (files: { path: string; text: string }[]) => auditFiles(files).findings.map(f => f.ruleId);

test('only privileged JWT role is flagged; raw JWT never leaves the report', () => {
  const token = jwt('service_role');
  const run = auditFiles([file('env.ts', 'const publicToken = "' + jwt('anon') + '";\nconst key = "' + token + '";')]);
  expect(run.findings.map(f => [f.ruleId,f.severity])).toEqual([['secret-supabase-role','critical']]);
  expect(JSON.stringify(run)).not.toContain(token);
  expect(JSON.stringify(run)).not.toContain(token.split('.')[2]);
});

test('migration state is replayed in filename order, including later disable', () => {
  const create = file('001.sql','create table public.orders (id bigint);');
  const enable = file('002.sql','alter table public.orders enable row level security;');
  expect(ids([enable, create])).toEqual([]);
  expect(auditFiles([create]).findings[0]).toMatchObject({ruleId:'db-table-rls',severity:'critical',file:'001.sql'});
  expect(ids([enable, create, file('003.sql','alter table public.orders disable row level security;')])).toEqual(['db-table-rls']);
});

test('a session lookup is not authorization unless unauthenticated requests are stopped', () => {
  const path = 'src/app/api/orders/route.ts';
  const good = 'import { currentUser } from "@clerk/nextjs/server"; export async function POST() { const user = await currentUser(); if (!user) return new Response(null,{status:401}); await db.orders.create({}); }';
  const bad = 'import { currentUser } from "@clerk/nextjs/server"; export async function POST() { await currentUser(); await db.orders.create({}); }';
  expect(ids([file(path,good)])).toEqual([]);
  expect(ids([file(path,bad)])).toContain('auth-route-mutation');
});

test('agent instruction formatting rule distinguishes literal slash escapes from hidden characters', () => {
  expect(ids([file('SKILL.md','A visible example: \\u200B')])).toEqual([]);
  expect(ids([file('SKILL.md','A hidden character: '+String.fromCharCode(8203))])).toContain('config-instruction-unicode');
});

test('lifecycle controls are detected without executing manifest commands', () => {
  const unsafe = {scripts:{preinstall:['curl', 'SOURCE_PLACEHOLDER', '|', 'sh'].join(' '),postinstall:['powershell', '-enc', 'INVALID_FIXTURE_PLACEHOLDER'].join(' ')}};
  const safe = {scripts:{preinstall:': # ' + unsafe.scripts.preinstall,postinstall:'node ./validate-local-config.cjs'}};
  expect(ids([file('package.json',JSON.stringify(unsafe))])).toEqual(['config-install-encoded','config-install-pipe']);
  expect(ids([file('package.json',JSON.stringify(safe))])).toEqual([]);
});

test('SARIF results link to a declared rule and preserve the source line', () => {
  const run = auditFiles([file('supabase/migrations/001.sql','-- inventory\ncreate table public.orders (id bigint);')]);
  const sarif = toSarif(run);
  const base = sarif.runs[0];
  expect(sarif.version).toBe('2.1.0');
  expect(base.tool.driver.rules.some(r => r.id === 'db-table-rls')).toBe(true);
  expect(base.results[0]).toMatchObject({ ruleId:'db-table-rls', locations:[{physicalLocation:{artifactLocation:{uri:'supabase/migrations/001.sql'},region:{startLine:2}}}] });
});

test('adjacent findings cannot disclose multiline private key bytes', () => {
  const marker = 'SYNTHETIC_PRIVATE_BODY_12345';
  const role = 'sb_secret_synthetic1234567890';
  const result = auditFiles([file('sample.ts', [
    'const pem = `-----BEGIN PRIVATE KEY-----',
    marker + ' ${eval(input)}',
    '-----END PRIVATE KEY-----`;',
    'const token = "' + role + '";',
    'const publishable = "sb_publishable_synthetic1234567890";',
  ].join('\n'))]);
  expect(result.findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['secret-pem','inject-eval','secret-supabase-secret']));
  expect(result.findings).toHaveLength(3);
  expect(JSON.stringify(result)).not.toContain(marker);
  expect(JSON.stringify(result)).not.toContain(role);
});

test('other findings and fallback output redact opaque public credential assignments', () => {
  for (const key of ['NEXT_PUBLIC_PRIVATE_KEY','NEXT_PUBLIC_SERVICE_ROLE','VITE_SECRET','EXPO_PUBLIC_API_KEY','NEXT_PUBLIC_TOKEN']) {
    const value = 'opaque-non-pem-secret-999';
    const source = 'const ' + key + ' = "' + value + '"; eval(x);';
    const run = auditFiles([file('adjacent.ts',source)]);
    expect(run.findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['secret-prefixed','inject-eval']));
    expect(JSON.stringify(run)).not.toContain(value);
    expect(redact(source)).not.toContain(value);
  }
  expect(redact('NEXT_PUBLIC_PRIVATE_KEY=opaque-env-value')).not.toContain('opaque-env-value');
});

test('multiline public assignments preserve line breaks and mask adjacent findings', () => {
  const value = 'wrapped-opaque-secret-777';
  for (const newline of ['\n','\r\n']) {
    const source = ['const k = {','  NEXT_PUBLIC_PRIVATE_KEY:', '    "' + value + '" + eval(x),','};','eval(y);'].join(newline);
    const result = auditFiles([file('wrapped.ts',source)]);
    expect(result.findings.filter(f => f.ruleId === 'inject-eval').map(f => f.line)).toEqual([3,5]);
    expect(result.findings.find(f => f.ruleId === 'secret-prefixed')?.line).toBe(2);
    expect(JSON.stringify(result)).not.toContain(value);
    expect(redact(source).split(newline)).toHaveLength(5);
    expect(redact(source)).not.toContain(value);
  }
});

test('comments between a public credential assignment and its literal cannot expose the value', () => {
  const value = 'opaque-comment-secret-4242';
  for (const source of [
    'const NEXT_PUBLIC_PRIVATE_KEY = /* rotated */ "' + value + '"; eval(x);',
    'const NEXT_PUBLIC_SERVICE_ROLE = // pinned\n  "' + value + '"; eval(x);',
    'const settings = { NEXT_PUBLIC_PRIVATE_KEY /* inline */: "' + value + '" }; eval(x);',
    'const NEXT_PUBLIC_PRIVATE_KEY = ("' + value + '"); eval(x);',
  ]) {
    const run = auditFiles([file('commented.ts',source)]);
    expect(run.findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['secret-prefixed','inject-eval']));
    expect(JSON.stringify(run)).not.toContain(value);
  }
});

test('an uncertain public credential value is withheld instead of echoed', () => {
  const value = 'opaque-uncertain-555';
  const dynamic = auditFiles([file('dynamic.ts','const NEXT_PUBLIC_PRIVATE_KEY = readValue("' + value + '"); eval(x);')]);
  expect(dynamic.findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['secret-prefixed','inject-eval']));
  expect(JSON.stringify(dynamic)).not.toContain(value);
  const broken = auditFiles([file('broken.ts','const NEXT_PUBLIC_PRIVATE_KEY = "' + value + '";\nconst broken = (;')]);
  expect(broken.findings.map(f => f.ruleId)).toEqual(['secret-prefixed']);
  expect(JSON.stringify(broken)).not.toContain(value);
  expect(broken.coverage.complete).toBe(false);
});

test('an unparseable credential-bearing JS file withholds excerpts from every analyzer', () => {
  const value = 'opaque-wrapped-parenthesized-9090';
  const source = [
    'module.exports = {',
    '  NEXT_PUBLIC_PRIVATE_KEY: ( // rotated',
    '    "' + value + '"), productionBrowserSourceMaps: true,',
    '};',
    'const broken = (;',
  ].join('\n');
  const run = auditFiles([file('next.config.js',source)]);
  expect(run.findings.map(f => f.ruleId)).toEqual(expect.arrayContaining(['config-sourcemaps','secret-prefixed']));
  expect(run.findings.every(f => f.snippet === '[Source excerpt withheld: unparseable credential-bearing file]')).toBe(true);
  expect(JSON.stringify(run)).not.toContain(value);
  expect(run.coverage.complete).toBe(false);
});

test('only resolved and unshadowed provider imports can establish verified identity', () => {
  const userCheck = 'const user = await currentUser(); if (!user) return;';
  const supabaseCheck = 'const {data:{user}} = await client.auth.getUser(); if (!user) return;';
  const scan = (top: string, body: string, params = '') => ids([file('app/api/orders/route.ts',top + ' export async function POST(' + params + ') {' + body + ' await db.orders.create({}); }')]);
  expect(scan('',userCheck)).toContain('auth-route-mutation');
  expect(scan('import {currentUser} from "untrusted";',userCheck)).toContain('auth-route-mutation');
  expect(scan('const currentUser = () => ({id:"fake"});',userCheck)).toContain('auth-route-mutation');
  expect(scan('', 'const user = await fakeClient.getUser(); if (!user) return;')).toContain('auth-route-mutation');
  expect(scan('',supabaseCheck)).toContain('auth-route-mutation');
  expect(scan('import {currentUser} from "@clerk/nextjs/server";',userCheck,'currentUser')).toContain('auth-route-mutation');
  expect(scan('import {currentUser} from "@clerk/nextjs/server";','function currentUser() { return {}; } ' + userCheck)).toContain('auth-route-mutation');
  expect(scan('import {currentUser as lookup} from "@clerk/nextjs/server"; const currentUser = lookup;',userCheck)).toEqual([]);
  expect(scan('import {createServerClient as factory} from "@supabase/ssr";', 'const client = factory(url,key);' + supabaseCheck)).toEqual([]);
  expect(scan('import {createServerClient} from "@supabase/ssr"; const client = createServerClient(url,key);',supabaseCheck)).toEqual([]);
  expect(scan('import {createClient} from "@/lib/supabase/server"; const client = await createClient();',supabaseCheck)).toContain('auth-route-mutation');
});

test('a local auth wrapper is trusted only when its own AST resolves to a recognized SDK', () => {
  const route = file('app/api/orders/route.ts','import {createClient} from "@/lib/supabase/server"; export async function POST() { const client = await createClient(); const {data:{user}} = await client.auth.getUser(); if (!user) return; await db.orders.create({}); }');
  const wrapper = (text: string) => file('lib/supabase/server.ts',text);
  const traced = wrapper('import { createServerClient } from "@supabase/ssr"; export async function createClient() { return createServerClient(url,key); }');
  const unbacked = wrapper('import { make } from "./client"; export async function createClient() { return make(); }');
  const fake = wrapper('export async function createClient() { return { auth: { getUser() {} } }; }');
  expect(ids([route])).toContain('auth-route-mutation');
  expect(ids([route,unbacked])).toContain('auth-route-mutation');
  expect(ids([route,fake])).toContain('auth-route-mutation');
  expect(ids([route,traced])).toEqual([]);
  expect(ids([route,wrapper('import { createServerClient } from "@supabase/ssr"; export const createClient = async () => createServerClient(url,key);')])).toEqual([]);
  expect(ids([route,wrapper('import { createServerClient } from "@supabase/ssr"; export async function createClient() { const client = createServerClient(url,key); return client; }')])).toEqual([]);
  expect(ids([route,wrapper('import { createServerClient } from "@supabase/ssr"; export async function createClient() { createServerClient(url,key); return { auth: { getUser() {} } }; }')])).toContain('auth-route-mutation');
  expect(ids([route,wrapper('import { createServerClient } from "@supabase/ssr"; export async function createClient() { if (flag) return createServerClient(url,key); return { auth: { getUser() {} } }; }')])).toContain('auth-route-mutation');
  expect(ids([route,wrapper('import { createServerClient } from "@supabase/ssr"; export async function createClient() { const client = createServerClient(url,key); client = fake; return client; }')])).toContain('auth-route-mutation');

  const clerkRoute = (top: string) => file('app/api/orders/route.ts', top + ' export async function POST() { const { userId } = await auth(); if (!userId) return; await db.orders.create({}); }');
  expect(ids([clerkRoute('import { auth } from "@/auth";')])).toContain('auth-route-mutation');
  expect(ids([clerkRoute('import { auth } from "@/auth";'),file('auth.ts','export { auth } from "@clerk/nextjs/server";')])).toEqual([]);
  expect(ids([clerkRoute('import { auth } from "@/auth";'),file('auth.ts','import { auth as lookup } from "untrusted"; export const auth = lookup;')])).toContain('auth-route-mutation');
});

test('a block-local fake cannot inherit an outer SDK alias', () => {
  const route = file('app/api/orders/route.ts','import {createClient} from "@/lib/supabase/server"; export async function POST() { const client = await createClient(); const {data:{user}} = await client.auth.getUser(); if (!user) return; await db.orders.create({}); }');
  const wrapper = (body: string) => file('lib/supabase/server.ts','import { createServerClient } from "@supabase/ssr"; export async function createClient() { const client = createServerClient(url,key); ' + body + ' }');
  expect(ids([route,wrapper('if (cond) { const client = fakeObj; return client; } return client;')])).toContain('auth-route-mutation');
  expect(ids([route,wrapper('if (cond) { const other = fakeObj; return other; } return client;')])).toContain('auth-route-mutation');
  expect(ids([route,wrapper('return client;')])).toEqual([]);
});

test('a switch-case alias cannot leak into the enclosing function scope', () => {
  const route = file('app/api/orders/route.ts','import {createClient} from "@/lib/supabase/server"; export async function POST() { const client = await createClient(); const {data:{user}} = await client.auth.getUser(); if (!user) return; await db.orders.create({}); }');
  const wrapper = (text: string) => file('lib/supabase/server.ts','import { createServerClient } from "@supabase/ssr"; ' + text);
  expect(ids([route,wrapper('const client = fakeObj; export async function createClient() { switch (flag) { case 1: const client = createServerClient(url,key); break; } return client; }')])).toContain('auth-route-mutation');
  expect(ids([route,wrapper('export async function createClient() { switch (flag) { case 1: return createServerClient(url,key); } return createServerClient(url,key); }')])).toEqual([]);
});

test('verified identity and signature must dominate writes', () => {
  const route = (body: string) => file('app/api/orders/route.ts', 'import {currentUser} from "@clerk/nextjs/server"; import {getServerSession} from "next-auth"; import {createServerClient} from "@supabase/ssr"; const supabase = createServerClient(url,key); export async function POST() {' + body + '}');
  const verify = 'const {data,error} = await supabase.auth.getUser();';
  const deny = 'if (error || !data?.user) return Response.json(null,{status:401});';
  const write = 'await db.orders.create({});';
  for (const bad of [verify + write, write + verify + deny, verify + 'if (false) await requireAuth();' + write, verify + 'if (!data) return;' + write]) {
    expect(ids([route(bad)])).toContain('auth-route-mutation');
  }
  expect(ids([route(verify + deny + write)])).toEqual([]);
  expect(ids([route('await requireAuth();' + write)])).toContain('auth-route-mutation');
  for (const helper of ['async function requireAuth() { return null; }', 'async function requireAuth() { const user = await currentUser(); if (!user) return null; return user; }']) {
    expect(ids([route(helper + 'await requireAuth();' + write)])).toContain('auth-route-mutation');
  }
  const verifiedHelper = 'async function requireAuth() { const user = await currentUser(); if (!user) throw new Error("Sign in"); return user; }';
  expect(ids([route('await requireAuth();' + write),file('unrelated.ts',verifiedHelper)])).toContain('auth-route-mutation');
  expect(ids([file('app/api/orders/route.ts',verifiedHelper + route('await requireAuth();' + write).text)])).toEqual([]);
  expect(ids([route('const session = await getServerSession(); if (!session?.user) throw new Error("Sign in");' + write)])).toEqual([]);
  const stripe = (body: string) => file('app/api/stripe/webhook/route.ts', 'export async function POST(request) {' + body + '}');
  const check = 'const event = stripe.webhooks.constructEvent(await request.text(),signature,secret);';
  expect(ids([stripe(write + check)])).toContain('auth-webhook-signature');
  expect(ids([stripe('state.processed = true;' + check)])).toContain('auth-webhook-signature');
  expect(ids([stripe('await processOrder(payload);' + check)])).toContain('auth-webhook-signature');
  expect(ids([stripe('const signature = request.headers.get("stripe-signature"); const body = Buffer.from(await request.arrayBuffer()); const event = stripe.webhooks.constructEvent(body,signature,secret);' + write)])).toEqual([]);
  expect(ids([stripe('try { ' + check + ' } catch { return new Response(null,{status:400}); }' + write)])).toEqual([]);
  expect(ids([stripe(check + write)])).toEqual([]);
});

test('policy widening and bucket flips replay across migrations, including restoration', () => {
  const base = file('001.sql', "CREATE TABLE orders (owner uuid); ALTER TABLE orders ENABLE ROW LEVEL SECURITY; CREATE POLICY own ON orders FOR UPDATE TO authenticated USING (owner = auth.uid()); INSERT INTO storage.buckets (id, public) VALUES ('orders', false);");
  const widen = file('002.sql', "ALTER POLICY own ON orders USING (true); UPDATE storage.buckets SET public = true WHERE id = 'orders';");
  const restore = file('003.sql', "ALTER POLICY own ON orders USING (owner = auth.uid()); UPDATE storage.buckets SET public = false WHERE id = 'orders';");
  expect(ids([widen,base]).sort()).toEqual(['db-policy-update','db-storage-public']);
  expect(ids([restore,widen,base])).toEqual([]);
  expect(auditFiles([file('004.sql', 'DO $$ BEGIN EXECUTE configured_statement; END $$;')])).toMatchObject({coverage:{complete:false}});
  expect(auditFiles([file('004.sql', 'ALTER POLICY own ON orders USING (')])).toMatchObject({coverage:{complete:false}});
});

test('ALTER VIEW and ALTER FUNCTION replay the effective security state', () => {
  const base = file('001.sql', "CREATE VIEW app.cards WITH (security_invoker = true) AS SELECT 1; CREATE FUNCTION app.read_card(user_id uuid) RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path = '' AS $$ SELECT user_id $$;");
  const alter = (sql: string) => file('002.sql',sql);
  expect(ids([base,alter('ALTER VIEW app.cards RESET (security_invoker);')])).toEqual(['db-view-invoker']);
  expect(ids([base,alter('ALTER VIEW app.cards SET (security_invoker = false);'),file('003.sql','ALTER VIEW app.cards SET (security_invoker = true);')])).toEqual([]);
  const definer = alter('ALTER FUNCTION app.read_card(uuid) SECURITY DEFINER;');
  expect(ids([base,definer])).toEqual(['db-definer-user']);
  expect(ids([base,definer,file('003.sql','ALTER FUNCTION app.read_card(uuid) RESET search_path;')]).sort()).toEqual(['db-definer-path','db-definer-user']);
  expect(ids([base,definer,file('003.sql','ALTER FUNCTION app.read_card(uuid) SECURITY INVOKER;')])).toEqual([]);
  expect(auditFiles([base,alter('ALTER VIEW app.cards OWNER TO another_role; ALTER FUNCTION app.read_card(uuid) SET statement_timeout = 1;')]).coverage.incompleteReasons).toHaveLength(2);
});

test('ALTER ROUTINE replays function security and reports unresolved routines', () => {
  const base = file('001.sql', "CREATE FUNCTION public.fn_name(a uuid) RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path = '' AS $$ SELECT a $$;");
  const definer = file('002.sql','ALTER ROUTINE public.fn_name(uuid) SECURITY DEFINER;');
  const reset = file('003.sql','ALTER ROUTINE public.fn_name(uuid) RESET search_path;');
  expect(ids([base,definer,reset])).toEqual(['db-definer-path']);
  expect(ids([base,definer,reset,file('004.sql',"ALTER ROUTINE public.fn_name(uuid) SET search_path = ''; ")])).toEqual([]);
  expect(ids([base,definer,reset,file('004.sql','ALTER ROUTINE public.fn_name(uuid) SECURITY INVOKER;')])).toEqual([]);
  expect(auditFiles([definer]).coverage.complete).toBe(false);
  expect(auditFiles([base,file('002.sql','ALTER ROUTINE public.fn_name(uuid) OWNER TO another_role;')]).coverage.complete).toBe(false);
});

test('SARIF uses direct relative artifact URIs and reports incomplete execution', () => {
  const report = toSarif(auditFiles([file('bad.ts','const value = ;'),file('001.sql','CREATE TABLE orders (id int);')])).runs[0];
  expect(report).not.toHaveProperty('originalUriBaseIds');
  expect(report.results[0].locations[0].physicalLocation.artifactLocation).toEqual({uri:'001.sql'});
  expect(report).toMatchObject({invocations:[{executionSuccessful:false,toolExecutionNotifications:[{level:'warning',message:{text:expect.stringMatching(/parse/i)}}]}]});
});
