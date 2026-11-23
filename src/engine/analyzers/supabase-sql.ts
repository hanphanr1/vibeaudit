import type { SourceFile } from '../loader';
import type { Hit } from '../types';
import { sourceHit } from './secrets';

const ident = '(?:"(?:[^"]|"")+"|[a-z_][a-z_0-9$]*)';
const qualified = '(' + ident + '(?:\\s*\\.\\s*' + ident + ')?)';
const tableCreate = new RegExp('^create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?' + qualified,'i');
const tableAlter = new RegExp('^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?' + qualified + '\\s+(.*)$','is');
const tableDrop = new RegExp('^drop\\s+table\\s+(?:if\\s+exists\\s+)?' + qualified,'i');
const viewCreate = new RegExp('^create\\s+(?:or\\s+replace\\s+)?(materialized\\s+)?view\\s+(?:if\\s+not\\s+exists\\s+)?' + qualified,'i');
const fnCreate = new RegExp('^create\\s+(?:or\\s+replace\\s+)?function\\s+' + qualified + '\\s*\\(([^)]*)\\)','is');
const fnChange = new RegExp('^(alter|drop)\\s+(?:function|routine)\\s+(?:if\\s+exists\\s+)?' + qualified + '\\s*\\(([^)]*)\\)\\s*(.*)$','is');
const viewChange = new RegExp('^(alter|drop)\\s+(?:materialized\\s+)?view\\s+(?:if\\s+exists\\s+)?' + qualified + '\\s*(.*)$','is');
const safePath = /^(?:''|""|pg_catalog|"pg_catalog")$/i;
const searchPath = /\bset\s+search_path\s*(?:=|\bto\b)\s*((?:''|""|pg_catalog\b|"pg_catalog")(?!\s*,))/i;
const policyCreate = new RegExp('^create\\s+policy\\s+(' + ident + ')\\s+on\\s+' + qualified,'i');
const policyAlter = new RegExp('^alter\\s+policy\\s+(' + ident + ')\\s+on\\s+' + qualified,'i');
const policyDrop = new RegExp('^drop\\s+policy\\s+(?:if\\s+exists\\s+)?(' + ident + ')\\s+on\\s+' + qualified,'i');
const sqlTokens = /--[^\n]*|\/\*[\s\S]*?\*\/|\$([a-z_][\w]*|)\$[\s\S]*?\$\1\$|'(?:''|[^'])*'|"(?:""|[^"])*"|;/gi;
const sqlLiterals = new RegExp(sqlTokens.source.slice(0,-2),'gi');
interface Policy { name: string; table: string; operation: string; roles: string; using?: string; check?: string; file: SourceFile; at: number }
interface FunctionSecurity { name: string; parameterTypes: string; definer: boolean; safePath: boolean; trustsUser: boolean; file: SourceFile; at: number }
const functionType = '(?:' + ident + '(?:\\s*\\.\\s*' + ident + ')?|double precision|character varying|(?:time|timestamp) (?:with|without) time zone)(?:\\s*\\[\\s*\\])*';
const typeOnly = new RegExp('^(' + functionType + ')$','i');
const namedType = new RegExp('^' + ident + '\\s+(' + functionType + ')$','i');

function functionKey(name: string, args: string): { identity: string; parameterTypes: string } | undefined {
  const types: string[] = [];
  for (const raw of args.trim() ? args.split(',') : []) {
    const input = raw.trim().replace(/\s+/g,' ');
    if (/^out\s/i.test(input)) continue;
    const argument = input.replace(/^(?:inout|in|variadic)\s+/i,'').split(/\s+(?:default\b|=)|\s*=/i,1)[0].trim();
    const type = typeOnly.exec(argument)?.[1] ?? namedType.exec(argument)?.[1];
    if (!type) return;
    const canonical = type.replace(/"(?:""|[^"])*"|[^"\s.\[\]]+/g, part => part.startsWith('"') ? part : part.toLowerCase()).replace(/\s*([.\[\]])\s*/g,'$1');
    types.push(canonical);
  }
  return {identity:key(name) + ':' + types.join(','), parameterTypes:types.join(', ')};
}
const unrestricted = /^\(*\s*true\s*\)*$/i;
const ownerCheck = /\b(?:owner(?:_id)?\s*=\s*\(?\s*(?:select\s+)?auth\.uid\s*\(|auth\.uid\s*\(\s*\)\s*(?:::text)?\s*=\s*owner(?:_id)?\b)/i;

function policyExpression(tail: string, start: RegExp): string | undefined {
  const match = start.exec(tail);
  if (!match) return;
  const begin = match.index + match[0].length;
  let depth = 1;
  for (const token of tail.slice(begin).matchAll(/'(?:''|[^'])*'|"(?:""|[^"])*"|[()]/g)) {
    if (token[0] === '(') depth++;
    if (token[0] === ')' && --depth === 0) return tail.slice(begin,begin + token.index).trim();
  }
  return '';
}

function statements(file: SourceFile) {
  const result: { sql: string; at: number }[] = [];
  let start = 0, current = '', position = 0;
  const add = () => { if (current.trim()) result.push({ sql: current.trim(), at: start + current.search(/\S/) }); };
  for (const match of file.text.matchAll(sqlTokens)) {
    const token = match[0];
    current += file.text.slice(position, match.index);
    position = match.index + token.length;
    if (token === ';') { add(); current = ''; start = position; }
    else current += token.startsWith('--') || token.startsWith('/*') ? token.replace(/[^\n]/g, ' ') : token;
  }
  current += file.text.slice(position);
  add();
  return result;
}

function key(name: string) {
  const parts = name.match(new RegExp(ident, 'gi'))!.map(part => part.startsWith('"') ? part.slice(1,-1).replace(/""/g,'"') : part.toLowerCase());
  return JSON.stringify(parts.length === 1 ? ['public', parts[0]] : parts);
}

export function analyzeSql(files: readonly SourceFile[], incompleteReasons: string[]): Hit[] {
  const tables = new Map<string,{ name: string; enabled: boolean; file: SourceFile; at: number }>();
  const views = new Map<string,Hit>();
  const knownViews = new Set<string>();
  const policies = new Map<string,Policy>();
  const functions = new Map<string,FunctionSecurity>();
  const buckets = new Map<string,Hit>();
  const sorted = files.filter(file => /\.sql$/i.test(file.path)).sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  for (const file of sorted) for (const { sql, at } of statements(file)) {
    const warning = (detail?: string) => incompleteReasons.push('Could not fully replay SQL in ' + file.path + ' at line ' + ((file.text.slice(0,at).match(/\n/g)?.length ?? 0) + 1) + (detail ? ': ' + detail : '.'));
    if (/^(?:do\b|execute\b|prepare\b|call\b)/i.test(sql) || (/\bexecute\b/i.test(sql) && fnCreate.test(sql))) { warning(); continue; }
    const structural = sql.replace(sqlLiterals,'');
    let depth = 0;
    if (/(?:['"]|\/\*|\$\w*\$)/.test(structural) || [...structural.matchAll(/[()]/g)].some(m => (depth += m[0] === '(' ? 1 : -1) < 0) || depth) { warning(); continue; }
    const create = tableCreate.exec(sql), alter = tableAlter.exec(sql), drop = tableDrop.exec(sql);
    if (create) {
      const name = create[1], id = key(name);
      if (!tables.has(id) || !/^create\s+table\s+if\s+not\s+exists/i.test(sql)) tables.set(id, { name, enabled:false, file, at });
      continue;
    }
    if (drop) {
      const id = key(drop[1]);
      tables.delete(id);
      for (const [policyId,policy] of policies) if (key(policy.table) === id) policies.delete(policyId);
      continue;
    }
    if (alter) {
      const id = key(alter[1]);
      const table = tables.get(id);
      if (table) {
        if (/^(enable|disable)\s+row\s+level\s+security/i.test(alter[2])) table.enabled = /^enable/i.test(alter[2]);
        const rename = new RegExp('^rename\\s+to\\s+(' + ident + ')$', 'i').exec(alter[2]);
        if (rename) {
          const parts = alter[1].match(new RegExp(ident, 'gi'))!;
          table.name = parts.length === 2 ? parts[0] + '.' + rename[1] : rename[1];
          tables.delete(id);
          tables.set(key(table.name), table);
        }
      }
      continue;
    }
    const view = viewCreate.exec(sql);
    if (view) {
      const name = view[2];
      const id = key(name);
      views.delete(id);
      if (view[1]) knownViews.delete(id);
      else knownViews.add(id);
      if (view[1]) views.set(key(name), sourceHit(file,'db-materialized-view',at,'REVOKE SELECT ON ' + name + ' FROM PUBLIC, anon, authenticated;', 'Assert anon and authenticated cannot select from ' + name + '.'));
      else if (!/\bwith\s*\(\s*[^)]*\bsecurity_invoker\s*=\s*(?:true|on)\b/i.test(sql)) views.set(key(name),sourceHit(file,'db-view-invoker',at,'ALTER VIEW ' + name + ' SET (security_invoker = true);','Assert the view does not return rows denied by the underlying RLS policies.'));
      continue;
    }
    const changeView = viewChange.exec(sql);
    if (changeView) {
      const [,operation,name,tail] = changeView;
      const id = key(name);
      if (/^drop$/i.test(operation) && /^(?:cascade|restrict)?$/i.test(tail)) { views.delete(id); knownViews.delete(id); continue; }
      const setting = /^set\s*\(\s*security_invoker\s*=\s*(true|on|false|off)\s*\)$/i.exec(tail);
      if (knownViews.has(id) && (setting || /^reset\s*\(\s*security_invoker\s*\)$/i.test(tail))) {
        if (setting && /^(?:true|on)$/i.test(setting[1])) views.delete(id);
        else views.set(id,sourceHit(file,'db-view-invoker',at,'ALTER VIEW ' + name + ' SET (security_invoker = true);','Assert the view does not return rows denied by the underlying RLS policies.'));
      } else warning('unsupported view alteration');
      continue;
    }
    if (/^(?:alter|drop)\s+(?:materialized\s+)?view\b/i.test(sql)) { warning(); continue; }
    if (/^revoke\s+(?:all(?:\s+privileges)?|select)\s+on\s+/i.test(sql)) {
      const revoke = new RegExp('^revoke\\s+(?:all(?:\\s+privileges)?|select)\\s+on\\s+(?:table\\s+)?' + qualified + '\\s+from\\s+(.*)$','i').exec(sql);
      if (revoke && ['public','anon','authenticated'].every(role => revoke[2].toLowerCase().split(/\s*,\s*/).includes(role)) && views.get(key(revoke[1]))?.ruleId === 'db-materialized-view') views.delete(key(revoke[1]));
    }
    const removePolicy = policyDrop.exec(sql);
    if (removePolicy) { policies.delete(key(removePolicy[2]) + key(removePolicy[1])); continue; }
    const original = policyCreate.exec(sql);
    const policy = original ?? policyAlter.exec(sql);
    if (policy) {
      const [,name,table] = policy;
      const id = key(table) + key(name), previous = original ? undefined : policies.get(id);
      if (!original && !previous) { warning(); continue; }
      const tail = sql.slice(policy[0].length);
      const operation = previous?.operation ?? /\bfor\s+(select|insert|update|delete|all)\b/i.exec(tail)?.[1].toLowerCase() ?? 'all';
      const roles = /\bto\s+(.+?)(?=\busing\s*\(|\bwith\s+check\s*\(|$)/is.exec(tail)?.[1] ?? previous?.roles ?? 'public';
      const using = policyExpression(tail,/\busing\s*\(/i) ?? previous?.using;
      const check = policyExpression(tail,/\bwith\s+check\s*\(/i) ?? previous?.check;
      if (using === '' || check === '' || (!original && !/^\s*(?:to\s|using\s*\(|with\s+check\s*\()/i.test(tail))) { warning(); continue; }
      policies.set(id,{name,table,operation,roles,using,check,file,at});
      continue;
    }
    if (/^(?:create|alter|drop)\s+policy\b/i.test(sql)) { warning(); continue; }
    const fn = fnCreate.exec(sql);
    if (fn) {
      const [,name,args] = fn;
      const signature = functionKey(name,args);
      if (!signature) { warning(); continue; }
      const tail = sql.slice(fn[0].length);
      const declaration = tail.replace(sqlLiterals, value => value.startsWith('$') ? ' ' : value);
      const param = /(?:^|,)\s*((?:p_)?user_id)\s+[a-z"_]/i.exec(args);
      functions.set(signature.identity,{name,parameterTypes:signature.parameterTypes,definer:/\bsecurity\s+definer\b/i.test(declaration),safePath:searchPath.test(declaration),trustsUser:!!param && new RegExp('\\b' + param[1] + '\\b','i').test(tail),file,at});
      continue;
    }
    const changeFunction = fnChange.exec(sql);
    if (changeFunction) {
      const [,operation,name,args,tail] = changeFunction;
      const signature = functionKey(name,args);
      const state = signature && functions.get(signature.identity);
      if (signature && /^drop$/i.test(operation) && /^(?:cascade|restrict)?$/i.test(tail)) { functions.delete(signature.identity); continue; }
      if (!state || !/^alter$/i.test(operation)) { warning('unresolved function signature'); continue; }
      const security = /^(?:external\s+)?security\s+(definer|invoker)$/i.exec(tail);
      const path = /^set\s+search_path\s*(?:(?:=|\bto\b)\s*(\S[\s\S]*)|from\s+current)$/i.exec(tail);
      if (security) { state.definer = /^definer$/i.test(security[1]); state.file = file; state.at = at; }
      else if (path || /^reset\s+search_path$/i.test(tail)) {
        if (path?.[1] && !/^(?:''|"(?:""|[^"])*"|[\w$]+)(?:\s*,\s*(?:"(?:""|[^"])*"|[\w$]+))*$/.test(path[1])) warning();
        state.safePath = !!path?.[1] && safePath.test(path[1]); state.file = file; state.at = at;
      } else warning('unsupported function alteration');
      continue;
    }
    if (/^(?:alter|drop)\s+(?:function|routine)\b/i.test(sql)) { warning(); continue; }
    const bucket = /^(?:insert\s+into|update|delete\s+from)\s+"?storage"?\s*\.\s*"?buckets"?(?=\s|\()/i.exec(sql);
    if (!bucket) {
      if (/^(?:alter|create|drop)\s+table\b/i.test(sql) || /^(?:with|merge|truncate|copy)\b[\s\S]*\bstorage\s*\.\s*buckets\b/i.test(sql)) warning();
      continue;
    }
    const tail = sql.slice(bucket[0].length).trim();
    const insert = /^\(([^)]+)\)\s*values\s*\(([^)]+)\)$/i.exec(tail);
    const update = /^set\s+"?public"?\s*=\s*(true|false)\s+where\s+"?id"?\s*=\s*('(?:''|[^'])*')$/i.exec(tail);
    const remove = /^where\s+"?id"?\s*=\s*('(?:''|[^'])*')$/i.exec(tail);
    let id: string | undefined, value: string | undefined;
    if (insert && /^insert/i.test(sql)) {
      const cols = insert[1].split(',').map(column => column.trim().toLowerCase().replaceAll('"',''));
      const vals = insert[2].match(/'(?:''|[^'])*'|[^,]+/g)?.map(part => part.trim()) ?? [];
      if (vals.length === cols.length) { id = vals[cols.indexOf('id')]; value = vals[cols.indexOf('public')] ?? 'false'; }
    } else if (update && /^update/i.test(sql)) { [,value,id] = update; }
    else if (remove && /^delete/i.test(sql)) { id = remove[1]; value = 'false'; }
    if (!id || !/^'(?:''|[^'])*'$/.test(id) || !value || !/^(true|false)$/i.test(value)) { warning(); continue; }
    if (/^true$/i.test(value)) buckets.set(id,sourceHit(file,'db-storage-public',at,'UPDATE storage.buckets SET public = false WHERE id = ' + id + ';','Assert anonymous reads are denied for objects in bucket ' + id + '.'));
    else buckets.delete(id);
  }
  const hits: Hit[] = [];
  for (const { name, enabled, file, at } of tables.values()) {
    if (!enabled) hits.push(sourceHit(file,'db-table-rls',at,'ALTER TABLE ' + name + ' ENABLE ROW LEVEL SECURITY;','Assert that anonymous access to ' + name + ' is denied and that intended users can only retrieve their own rows.'));
  }
  hits.push(...views.values(), ...buckets.values());
  for (const {name,table,operation,roles,using,check,file,at} of policies.values()) {
    if (!roles.split(',').some(role => /^(?:public|anon|authenticated)$/i.test(role.trim().replace(/^"|"$/g,'')))) continue;
    const patch = 'DROP POLICY ' + name + ' ON ' + table + ';';
    if (operation !== 'select' && (unrestricted.test(using ?? '') || unrestricted.test(check ?? ''))) hits.push(sourceHit(file,'db-policy-' + operation,at,patch,'Assert an authenticated user cannot ' + operation + ' rows owned by another user. Restore only the intended owner-scoped grants.'));
    if (key(table) === key('storage.objects') && !ownerCheck.test(using ?? '') && !ownerCheck.test(check ?? '')) hits.push(sourceHit(file,'db-storage-owner',at,patch,'Assert members of the same bucket cannot access another owner’s private object.'));
  }
  for (const {name,parameterTypes,definer,safePath,trustsUser,file,at} of functions.values()) {
    if (!definer) continue;
    if (!safePath) hits.push(sourceHit(file,'db-definer-path',at,"ALTER FUNCTION " + name + '(' + parameterTypes + ") SET search_path = '';\n-- Schema-qualify all objects in the function body.",'Assert the function resolves only explicitly trusted database objects.'));
    if (trustsUser) hits.push(sourceHit(file,'db-definer-user',at,'-- In ' + name + ', compare ownership against auth.uid(), not the caller-supplied user ID.\nIF auth.uid() IS NULL THEN RAISE EXCEPTION \'Authentication required\'; END IF;','Assert caller-supplied user identifiers cannot change which rows are returned.'));
  }
  return hits;
}
