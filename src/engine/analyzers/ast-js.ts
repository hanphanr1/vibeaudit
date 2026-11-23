import { parse } from '@babel/parser';
import { posix } from 'node:path';
import type { SourceFile } from '../loader';
import type { Hit } from '../types';
import { sourceHit } from './secrets';

type Node = { type: string; start?: number | null; [key: string]: any };
const tests = { require: /^(?:requireAuth|requireSession|requireStoreFor)$/, mutation: /^(?:insert|update|upsert|delete|deleteMany|create|createMany|save|remove|set|writeFile|appendFile|revalidatePath|revalidateTag|mutate)$/ };
const functions = new Set(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod','ClassMethod']);

function visit(node: Node | undefined, fn: (node: Node) => void, skipFunctions = false) {
  if (!node || typeof node.type !== 'string') return;
  fn(node);
  for (const [key,val] of Object.entries(node)) {
    if (key === 'loc' || key.endsWith('Comments') || key === 'extra') continue;
    for (const child of Array.isArray(val) ? val : [val]) if (child && typeof child === 'object' && (!skipFunctions || !functions.has(child.type))) visit(child,fn,skipFunctions);
  }
}

function name(node?: Node): string {
  if (!node) return '';
  if (node.type === 'Identifier' || node.type === 'JSXIdentifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') return name(node.property);
  return '';
}

function call(node: Node): boolean {
  return node.type === 'CallExpression' || node.type === 'OptionalCallExpression';
}

function follows(node: Node | undefined, fn: (node: Node) => boolean): boolean {
  let found = false;
  visit(node, item => { if (fn(item)) found = true; },true);
  return found;
}

function objectValue(node: Node | undefined, key: string): Node | undefined {
  return node?.type === 'ObjectExpression' ? node.properties.find((p: Node) => name(p.key) === key)?.value : undefined;
}

function rootName(node?: Node): string {
  while (node?.type === 'MemberExpression' || node?.type === 'OptionalMemberExpression') node = node.object;
  return name(node);
}

function exits(node?: Node): boolean {
  if (node?.type === 'ThrowStatement') return true;
  if (node?.type === 'ReturnStatement') return true;
  return node?.type === 'BlockStatement' && exits(node.body.at(-1));
}

function accessPath(node?: Node): string {
  if (node?.type === 'MemberExpression' || node?.type === 'OptionalMemberExpression') {
    if (node.computed && node.property.type !== 'StringLiteral') return '';
    const parent = accessPath(node.object);
    const property = name(node.property);
    return parent && property && !property.includes('.') ? parent + '.' + property : '';
  }
  return node?.type === 'Identifier' ? node.name : '';
}

function bindIdentity(pattern: Node | undefined, path: string, out: Set<string>) {
  if (pattern?.type === 'Identifier') out.add(pattern.name + path);
  if (pattern?.type === 'ObjectPattern' && path.startsWith('.')) for (const p of pattern.properties as Node[]) {
    const property = '.' + name(p.key);
    if (path === property || path.startsWith(property + '.')) bindIdentity(p.value, path.slice(property.length), out);
  }
}

function write(node: Node): boolean {
  const target = node.type === 'AssignmentExpression' ? node.left : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : undefined;
  if (target?.type === 'MemberExpression' || target?.type === 'OptionalMemberExpression') return true;
  return call(node) && (tests.mutation.test(name(node.callee)) || /^(?:record|publish|dispatch|enqueue|send|emit|fetch|destroy|increment|decrement|commit|execute|query)$/.test(name(node.callee)));
}

function denied(test: Node, known: Set<string>): boolean {
  if (test.type === 'LogicalExpression' && test.operator === '||') return denied(test.left,known) || denied(test.right,known);
  if (test.type !== 'UnaryExpression' || test.operator !== '!') return false;
  return known.has(accessPath(test.argument));
}

function throwsOnDenial(node?: Node): boolean {
  if (node?.type === 'ThrowStatement') return true;
  if (node?.type !== 'BlockStatement') return false;
  for (const statement of node.body as Node[]) {
    if (statement.type === 'ThrowStatement') return true;
    if (statement.type !== 'ExpressionStatement' && statement.type !== 'VariableDeclaration') return false;
  }
  return false;
}

function stripeRead(node: Node, requests: ReadonlySet<string>, headers: ReadonlySet<string>): boolean {
  if (node.type === 'NewExpression') return /^(?:Response|Error)$/.test(name(node.callee));
  if (!call(node)) return true;
  const path = accessPath(node.callee);
  const method = name(node.callee), receiver = accessPath(node.callee.object);
  if (path === 'headers' || path === 'Buffer.from' || /^(?:Response|NextResponse)\.json$/.test(path) || /^console\.(?:log|info|warn|error|debug)$/.test(path)) return true;
  if (method === 'get' && call(node.callee.object ?? {type:''}) && accessPath(node.callee.object.callee) === 'headers') return true;
  if (method === 'get' && (headers.has(receiver) || [...requests].some(req => receiver === req + '.headers'))) return true;
  return (method === 'text' || method === 'arrayBuffer') && requests.has(receiver);
}

interface StripeGuard { signature: (node: Node) => boolean; requests: ReadonlySet<string>; headers: ReadonlySet<string> }

type Provider = 'factory' | 'supabase' | 'user' | 'session' | 'clerk-auth';
type Providers = ReadonlyMap<string,Provider>;

const sdkModules = new Set(['@clerk/nextjs','@clerk/nextjs/server','next-auth','next-auth/next','better-auth']);
const factoryModules = new Set(['@supabase/ssr','@supabase/supabase-js']);

function importedProvider(module: string, symbol: string): Provider | undefined {
  const clerk = module === '@clerk/nextjs' || module === '@clerk/nextjs/server';
  if (sdkModules.has(module) && symbol === 'currentUser') return 'user';
  if (sdkModules.has(module) && symbol === 'auth') return clerk ? 'clerk-auth' : 'session';
  if ((module === 'next-auth' || module === 'next-auth/next') && symbol === 'getServerSession') return 'session';
  if (factoryModules.has(module) && /^(?:createClient|createServerClient)$/.test(symbol)) return 'factory';
}

const parses = new WeakMap<SourceFile, Node | null>();
export type ProviderBinding = Provider;

function programOf(file: SourceFile): Node | null {
  if (parses.has(file)) return parses.get(file) ?? null;
  const typescript = /\.[cm]?tsx?$/i.test(file.path);
  let program: Node | null = null;
  if (/\.[cm]?[jt]sx?$/i.test(file.path)) {
    try { program = parse(file.text,{ sourceType:'unambiguous', plugins: [...(typescript ? ['typescript' as const] : []), ...(!typescript || /tsx$/i.test(file.path) ? ['jsx' as const] : [])] }).program; }
    catch { program = null; }
  }
  parses.set(file,program);
  return program;
}

function sdkBindings(program: Node): Map<string,Provider> {
  const bindings = new Map<string,Provider>();
  for (const statement of program.body as Node[]) {
    if (statement.type !== 'ImportDeclaration' || statement.importKind === 'type') continue;
    for (const spec of statement.specifiers as Node[]) {
      if (spec.importKind === 'type') continue;
      const local = name(spec.local);
      if (spec.type === 'ImportNamespaceSpecifier') {
        for (const symbol of ['currentUser','auth','getServerSession','createClient','createServerClient']) {
          const provider = importedProvider(statement.source.value,symbol);
          if (provider) bindings.set(local + '.' + symbol,provider);
        }
        continue;
      }
      const provider = importedProvider(statement.source.value,spec.type === 'ImportDefaultSpecifier' ? 'default' : name(spec.imported));
      if (provider) bindings.set(local,provider);
    }
  }
  return bindings;
}

const sdkSymbols = ['currentUser','auth','getServerSession','createClient','createServerClient'];

function unwrapExpression(node: Node | undefined): Node | undefined {
  while (node?.type === 'AwaitExpression' || node?.type === 'TSAsExpression' || node?.type === 'TSNonNullExpression' || node?.type === 'TSSatisfiesExpression' || node?.type === 'ParenthesizedExpression') node = node.argument ?? node.expression;
  return node;
}

function factoryCall(node: Node | undefined, direct: Providers, shadowed: ReadonlySet<string>): boolean {
  const value = unwrapExpression(node);
  return !!value && call(value) && direct.get(accessPath(value.callee)) === 'factory' && !shadowed.has(rootName(value.callee));
}

interface WrapperBinding { kind: 'const' | 'other'; init?: Node }

function wrapperFactory(fn: Node, direct: Providers): boolean {
  const body = fn.body;
  if (!body) return false;
  const shadowed = new Set<string>();
  const declared = new Map<string, number>();
  const reassigned = new Set<string>();
  const scopes: Map<string,WrapperBinding>[] = [new Map()];
  const returns: { value?: Node; scopes: Map<string,WrapperBinding>[] }[] = [];
  let dynamicScope = false;
  const declare = (name: string, binding: WrapperBinding) => {
    if (!name) return;
    shadowed.add(name);
    declared.set(name,(declared.get(name) ?? 0) + 1);
    scopes[scopes.length - 1].set(name,binding);
  };
  for (const param of fn.params as Node[]) visit(param,n => { if (n.type === 'Identifier') declare(n.name,{ kind:'other' }); },true);
  const walk = (node: Node | undefined) => {
    if (!node || typeof node.type !== 'string') return;
    if (node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') {
      if (node.id?.type === 'Identifier') declare(node.id.name,{ kind:'other' });
      return;
    }
    if (functions.has(node.type)) return;
    if (node.type === 'CatchClause') {
      scopes.push(new Map());
      if (node.param) visit(node.param,n => { if (n.type === 'Identifier') declare(n.name,{ kind:'other' }); },true);
      walk(node.body);
      scopes.pop();
      return;
    }
    if (node.type === 'WithStatement') {
      dynamicScope = true;
      return;
    }
    if (node.type === 'SwitchStatement') {
      walk(node.discriminant);
      scopes.push(new Map());
      for (const clause of node.cases as Node[]) walk(clause);
      scopes.pop();
      return;
    }
    if (node.type === 'BlockStatement' || /^For(?:In|Of)?Statement$/.test(node.type)) {
      scopes.push(new Map());
      for (const [key,value] of Object.entries(node)) {
        if (key === 'loc' || key === 'extra' || key.endsWith('Comments')) continue;
        for (const child of Array.isArray(value) ? value : [value]) if (child && typeof child === 'object') walk(child as Node);
      }
      scopes.pop();
      return;
    }
    if (node.type === 'VariableDeclaration') {
      for (const item of node.declarations as Node[]) {
        walk(item.init);
        if (item.id?.type === 'Identifier') declare(item.id.name,{ kind: node.kind === 'const' ? 'const' : 'other', init: item.init });
        else if (item.id) visit(item.id,n => { if (n.type === 'Identifier') declare(n.name,{ kind:'other' }); },true);
      }
      return;
    }
    if (node.type === 'ReturnStatement') {
      returns.push({ value: node.argument ?? undefined, scopes: [...scopes] });
      walk(node.argument);
      return;
    }
    if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete')) {
      const target = node.left ?? node.argument;
      if (target) reassigned.add(rootName(target));
    }
    for (const [key,value] of Object.entries(node)) {
      if (key === 'loc' || key === 'extra' || key.endsWith('Comments')) continue;
      for (const child of Array.isArray(value) ? value : [value]) if (child && typeof child === 'object') walk(child as Node);
    }
  };
  walk(body);
  if (dynamicScope) return false;
  const resolves = (value: Node | undefined, chain: Map<string,WrapperBinding>[]): boolean => {
    const resolved = unwrapExpression(value);
    if (!resolved) return false;
    if (factoryCall(resolved,direct,shadowed)) return true;
    if (resolved.type !== 'Identifier' || reassigned.has(resolved.name) || declared.get(resolved.name) !== 1) return false;
    let binding: WrapperBinding | undefined;
    for (let i = chain.length - 1; i >= 0 && !binding; i--) binding = chain[i].get(resolved.name);
    return !!binding && binding.kind === 'const' && factoryCall(binding.init,direct,shadowed);
  };
  if (body.type !== 'BlockStatement') return factoryCall(body,direct,shadowed);
  return returns.length > 0 && returns.every(item => resolves(item.value,item.scopes));
}

function exportProviders(program: Node): Map<string,Provider> {
  const direct = sdkBindings(program);
  const exported = new Map<string,Provider>();
  for (const statement of program.body as Node[]) {
    if (statement.type === 'ExportAllDeclaration') {
      for (const symbol of sdkSymbols) {
        const provider = importedProvider(statement.source.value,symbol);
        if (provider) exported.set(symbol,provider);
      }
      continue;
    }
    if (statement.type !== 'ExportNamedDeclaration') continue;
    if (statement.source && statement.exportKind !== 'type') {
      for (const spec of statement.specifiers as Node[]) {
        if (spec.type !== 'ExportSpecifier' || spec.exportKind === 'type') continue;
        const provider = importedProvider(statement.source.value,name(spec.local));
        if (provider) exported.set(name(spec.exported),provider);
      }
      continue;
    }
    const declaration = statement.declaration;
    if (!declaration && !statement.source) {
      for (const spec of statement.specifiers as Node[]) {
        const provider = direct.get(name(spec.local));
        if (provider) exported.set(name(spec.exported),provider);
      }
      continue;
    }
    if (declaration?.type === 'VariableDeclaration') for (const item of declaration.declarations as Node[]) {
      const init = item.init?.type === 'AwaitExpression' ? item.init.argument : item.init;
      const provider = init ? direct.get(accessPath(init)) : undefined;
      if (provider && name(item.id)) exported.set(name(item.id),provider);
      if (init && functions.has(init.type) && /^create/.test(name(item.id)) && wrapperFactory(init,direct)) exported.set(name(item.id),'factory');
    }
    if (declaration?.type === 'FunctionDeclaration' && declaration.id && /^create/.test(name(declaration.id)) && wrapperFactory(declaration,direct)) exported.set(name(declaration.id),'factory');
  }
  return exported;
}

const extensions = ['.ts','.tsx','.js','.jsx','.mjs','.cjs'];

function resolveLocal(importer: string, specifier: string, known: ReadonlySet<string>): string | undefined {
  let base: string;
  if (specifier.startsWith('@/')) base = specifier.slice(2);
  else if (specifier.startsWith('./') || specifier.startsWith('../')) base = posix.normalize(posix.join(posix.dirname(importer),specifier));
  else return;
  base = base.replace(/\.(?:[cm]?[jt]sx?)$/,'');
  const candidates = [base,...extensions.map(extension => base + extension),...extensions.map(extension => base + '/index' + extension)];
  return candidates.find(candidate => known.has(candidate));
}

export function localProviderBindings(files: readonly SourceFile[]): Map<string, Map<string,Provider>> {
  const programs = new Map<string,Node>();
  for (const file of files) {
    const program = programOf(file);
    if (program) programs.set(file.path,program);
  }
  const known = new Set(programs.keys());
  const exportsByPath = new Map<string,Map<string,Provider>>();
  for (const [path,program] of programs) exportsByPath.set(path,exportProviders(program));
  const result = new Map<string, Map<string,Provider>>();
  for (const [importer,program] of programs) {
    const bindings = new Map<string,Provider>();
    for (const statement of program.body as Node[]) {
      if (statement.type !== 'ImportDeclaration' || statement.importKind === 'type') continue;
      const target = resolveLocal(importer,statement.source.value,known);
      const providers = target && exportsByPath.get(target);
      if (!providers) continue;
      for (const spec of statement.specifiers as Node[]) {
        if (spec.importKind === 'type') continue;
        const local = name(spec.local);
        if (spec.type === 'ImportNamespaceSpecifier') {
          for (const [exported,provider] of providers) bindings.set(local + '.' + exported,provider);
          continue;
        }
        const provider = providers.get(spec.type === 'ImportDefaultSpecifier' ? 'default' : name(spec.imported));
        if (provider) bindings.set(local,provider);
      }
    }
    if (bindings.size) result.set(importer,bindings);
  }
  return result;
}

function deriveProviders(declaration: Node | undefined, providers: Map<string,Provider>, reassigned: ReadonlySet<string>) {
  if (declaration?.type !== 'VariableDeclaration' || declaration.kind !== 'const') return;
  for (const {id,init} of declaration.declarations as Node[]) {
    if (id.type !== 'Identifier' || reassigned.has(id.name)) continue;
    const value = init?.type === 'AwaitExpression' ? init.argument : init;
    if (!value) continue;
    const provider = value.type === 'CallExpression' ? (providers.get(accessPath(value.callee)) === 'factory' ? 'supabase' : undefined) : providers.get(accessPath(value));
    if (provider) providers.set(id.name,provider);
  }
}

function unshadowed(fn: Node, imported: Providers): Map<string,Provider> {
  const shadowed = new Set<string>();
  const collect = (pattern: Node) => visit(pattern,n => { if (n.type === 'Identifier') shadowed.add(n.name); });
  for (const param of fn.params as Node[]) collect(param);
  visit(fn.body,n => {
    if (n.type === 'VariableDeclarator' || n.type === 'FunctionDeclaration' || n.type === 'ClassDeclaration') collect(n.id);
    if (n.type === 'CatchClause') collect(n.param);
  });
  return new Map([...imported].filter(([binding]) => !shadowed.has(binding.split('.')[0])));
}

function identityPath(callee: Node, providers: Providers): string | undefined {
  const path = accessPath(callee);
  if (path.endsWith('.auth.getUser') && providers.get(path.slice(0,-'.auth.getUser'.length)) === 'supabase') return '.data.user';
  switch (providers.get(path)) {
    case 'user': return '';
    case 'session': return '.user';
    case 'clerk-auth': return '.userId';
  }
}
const noReassignments: ReadonlySet<string> = new Set();

function guardBeforeWrite(body: Node | undefined, stripe?: StripeGuard, localGuards?: ReadonlySet<string>, helper = false, imported?: Providers, reassigned = noReassignments): boolean {
  const providers = new Map(imported);
  const known = new Set<string>();
  const headers = new Set(stripe?.headers);
  if (body?.type !== 'BlockStatement') return false;
  for (const statement of body.body as Node[]) {
    if (stripe && statement.type === 'TryStatement' && statement.handler && !statement.finalizer &&
        exits(statement.handler.body) && !follows(statement.handler.body,n => write(n) || !stripeRead(n,stripe.requests,headers)) &&
        guardBeforeWrite(statement.block,{...stripe,headers})) return true;
    if (follows(statement,write)) return false;
    if (helper && follows(statement,n => /^(?:Return|Try)Statement$/.test(n.type))) return false;
    const expressions: Node[] = statement.type === 'ExpressionStatement' ? [statement.expression] :
      statement.type === 'VariableDeclaration' ? statement.declarations : [];
    for (const expression of expressions) {
      const value = expression.type === 'VariableDeclarator' ? expression.init : expression;
      const evaluation = value?.type === 'AssignmentExpression' && value.operator === '=' && value.left.type === 'Identifier' ? value.right : value;
      const awaited = evaluation?.type === 'AwaitExpression';
      const direct = awaited ? evaluation.argument : evaluation;
      if (direct && call(direct)) {
        const method = name(direct.callee);
        if (stripe && stripe.signature(direct) && (awaited || method === 'constructEvent') &&
            !follows(statement,n => n !== direct && !stripeRead(n,stripe.requests,headers))) return true;
        if (stripe && expression.type === 'VariableDeclarator' && accessPath(direct.callee) === 'headers' && expression.id.type === 'Identifier') headers.add(expression.id.name);
        if (!stripe && awaited && direct.type === 'CallExpression' && direct.callee.type === 'Identifier' && localGuards?.has(method)) return true;
        if (!stripe && expression.type === 'VariableDeclarator' && awaited && direct.type === 'CallExpression') {
          const identity = identityPath(direct.callee,providers);
          if (identity !== undefined) bindIdentity(expression.id,identity,known);
        }
      } else if (!stripe && expression.type === 'VariableDeclarator') {
        const from = accessPath(direct);
        for (const identity of [...known]) if (from && (identity === from || identity.startsWith(from + '.'))) bindIdentity(expression.id,identity.slice(from.length),known);
      }
    }
    if (stripe && follows(statement,n => !stripeRead(n,stripe.requests,headers))) return false;
    if (!stripe && statement.type === 'IfStatement' && (helper ? throwsOnDenial(statement.consequent) : exits(statement.consequent)) && denied(statement.test,known)) return true;
    if (!stripe) deriveProviders(statement,providers,reassigned);
    if (follows(statement, n => n.type === 'AssignmentExpression' || n.type === 'UpdateExpression')) { known.clear(); headers.clear(); }
  }
  return false;
}

export function analyzeJs(file: SourceFile, localProviders?: Providers): { hits: Hit[]; skipped: boolean } {
  const hits: Hit[] = [];
  if (!/\.[cm]?[jt]sx?$/i.test(file.path)) return { hits, skipped:false };
  let program: Node;
  const typescript = /\.[cm]?tsx?$/i.test(file.path);
  try { program = parse(file.text,{ sourceType:'unambiguous', plugins: [...(typescript ? ['typescript' as const] : []), ...(!typescript || /tsx$/i.test(file.path) ? ['jsx' as const] : [])] }).program; }
  catch { return { hits, skipped:true }; }
  const emit = (node: Node, id: string, patch: string, test: string, snippet?: string) => hits.push(sourceHit(file,id,node.start ?? 0,patch,test,snippet));
  const directive = (value: string) => program.directives?.some((d: Node) => d.value.value === value);
  const action = directive('use server');
  const client = directive('use client');
  const route = /(?:^|\/)app\/api\/(?!auth\/).*\/route\.[cm]?[jt]sx?$/i.test(file.path);
  const webhook = route && /stripe|webhooks?/i.test(file.path);
  const server = route || action || /(?:^|\/)(?:middleware|proxy)\.[jt]s$/i.test(file.path);
  const shellModules = new Set<string>();
  const shellFunctions = new Set<string>();
  const verifiedJwtBindings = new Set<string>();
  const imported = new Map<string,Provider>(localProviders ? [...localProviders] : []);
  const reassigned = new Set<string>();
  const nodes: Node[] = [];
  visit(program, node => {
    nodes.push(node);
    if (node.type === 'ImportDeclaration' && node.importKind !== 'type') for (const spec of node.specifiers as Node[]) {
      if (spec.importKind === 'type') continue;
      const module = node.source.value;
      const binding = name(spec.local);
      const symbols = spec.type === 'ImportNamespaceSpecifier' ? ['currentUser','auth','getServerSession','createClient','createServerClient','createSupabaseClient','createServerSupabaseClient'] : [spec.type === 'ImportDefaultSpecifier' ? 'default' : name(spec.imported)];
      for (const symbol of symbols) {
        const provider = importedProvider(module,symbol);
        if (provider) imported.set(spec.type === 'ImportNamespaceSpecifier' ? binding + '.' + symbol : binding,provider);
      }
    }
    if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete')) {
      const target = node.left ?? node.argument;
      if (target?.type === 'ObjectPattern' || target?.type === 'ArrayPattern') visit(target,n => { if (n.type === 'Identifier') reassigned.add(n.name); });
      else reassigned.add(rootName(target));
    }
    if (node.type === 'ImportDeclaration' && /^(?:node:)?child_process$/.test(node.source.value)) for (const spec of node.specifiers as Node[]) {
      if (spec.type !== 'ImportSpecifier') shellModules.add(name(spec.local));
      else if (/^exec(?:Sync)?$/.test(name(spec.imported))) shellFunctions.add(name(spec.local));
    }
    if (node.type === 'VariableDeclarator' && call(node.init ?? {type:''}) && name(node.init.callee) === 'require' && /^(?:node:)?child_process$/.test(name(node.init.arguments[0]))) {
      if (node.id.type === 'Identifier') shellModules.add(name(node.id));
      if (node.id.type === 'ObjectPattern') for (const p of node.id.properties as Node[]) if (/^exec(?:Sync)?$/.test(name(p.key))) shellFunctions.add(name(p.value));
    }
    if (call(node) && name(node.callee) === 'verify' && /^(?:jwt|jsonwebtoken)$/i.test(rootName(node.callee))) verifiedJwtBindings.add(name(node.arguments[0]));
  });
  const exported = new Map<string,Node>();
  const local = new Map<string,Node>();
  for (const binding of imported.keys()) if (reassigned.has(binding.split('.')[0])) imported.delete(binding);
  for (const statement of program.body as Node[]) {
    const declaration = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
    deriveProviders(declaration,imported,reassigned);
    if (declaration?.type === 'FunctionDeclaration' && declaration.id) {
      local.set(name(declaration.id),declaration);
      if (statement.type === 'ExportNamedDeclaration') exported.set(name(declaration.id),declaration);
    }
    if (declaration?.type === 'VariableDeclaration') for (const d of declaration.declarations as Node[]) if (name(d.id) && d.init) {
      local.set(name(d.id),d.init);
      if (statement.type === 'ExportNamedDeclaration') exported.set(name(d.id),d.init);
    }
  }
  for (const node of program.body as Node[]) if (node.type === 'ExportNamedDeclaration' && !node.source) for (const spec of node.specifiers as Node[]) {
    const decl = local.get(name(spec.local));
    if (decl) exported.set(name(spec.exported),decl);
  }
  const verified = new Set<string>();
  for (const [symbol,fn] of local) if (tests.require.test(symbol) && functions.has(fn.type) && guardBeforeWrite(fn.body,undefined,undefined,true,unshadowed(fn,imported),reassigned)) verified.add(symbol);
  for (const node of nodes) if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression') verified.delete(name(node.left ?? node.argument));

  for (const [symbol, fn] of exported) {
    if (!functions.has(fn.type)) continue;
    const mutating = /^(POST|PUT|PATCH|DELETE)$/.test(symbol);
    const stripe = webhook && mutating && (/stripe/i.test(file.path) || follows(fn.body,n => /^(?:constructEvent(?:Async)?|stripe-signature)$/.test(name(n.callee) || name(n))));
    const signature = stripe && guardBeforeWrite(fn.body, {
      signature: n => /^constructEvent(?:Async)?$/.test(name(n.callee)) && name(n.callee.object) === 'webhooks' && /stripe/i.test(rootName(n.callee)),
      requests: new Set<string>(fn.params.filter((param: Node) => param.type === 'Identifier').slice(0,1).map(name)), headers: new Set(),
    });
    const json = stripe && follows(fn.body, n => call(n) && name(n.callee) === 'json' && /^(?:req|request)$/i.test(rootName(n.callee)));
    if (stripe && !signature) emit(fn,'auth-webhook-signature','// At the start of ' + symbol + '\nconst body = await request.text();\nconst event = stripe.webhooks.constructEvent(body, signature, webhookSecret);','Assert an invalid signature is rejected and no webhook side effects run.');
    if (json) emit(fn,'auth-webhook-body','// In ' + symbol + '\n- await request.json()\n+ await request.text()','Assert a valid signature over the exact original text is accepted.');
    const routeFinding = route && mutating && !stripe;
    const actionFinding = (action || fn.body?.directives?.some((d: Node) => d.value.value === 'use server')) && fn.async && follows(fn.body,write);
    const localGuards = new Set(verified);
    for (const param of fn.params as Node[]) {
      const bound = new Set<string>();
      bindIdentity(param,'',bound);
      for (const value of bound) localGuards.delete(value);
    }
    visit(fn.body,n => {
      if (n.type === 'VariableDeclarator' || n.type === 'FunctionDeclaration') {
        const pattern = n.id;
        for (const guard of localGuards) if (follows(pattern, child => child.type === 'Identifier' && child.name === guard)) localGuards.delete(guard);
      }
    });
    if ((routeFinding || actionFinding) && !guardBeforeWrite(fn.body,undefined,localGuards,false,unshadowed(fn,imported),reassigned)) emit(fn,routeFinding ? 'auth-route-mutation' : 'auth-server-action','// Before side effects in ' + symbol + ', obtain verified identity and explicitly reject a missing user.\nconst { data: { user }, error } = await supabase.auth.getUser();\nif (error || !user) throw new Error("Authentication required");','Assert an unauthenticated call to ' + symbol + ' cannot change application state.');
  }

  for (const node of nodes) {
    if (node.type === 'JSXAttribute' && name(node.name) === 'dangerouslySetInnerHTML') {
      const html = objectValue(node.value?.expression,'__html');
      if (html && html.type !== 'StringLiteral' && !(call(html) && name(html.callee) === 'sanitize' && /^(?:DOMPurify|dompurify|purify)$/i.test(rootName(html.callee)))) {
        const value = name(html) || 'html';
        emit(node,'inject-html','// Render as text, or if markup is required:\n{ __html: DOMPurify.sanitize(' + value + ') }','Assert stored markup is sanitized before rendering.');
      }
    }
    if (node.type === 'ObjectProperty' && name(node.key) === 'dangerouslyAllowBrowser' && node.value?.type === 'BooleanLiteral' && node.value.value) emit(node,'secret-ai-browser','- dangerouslyAllowBrowser: true\n+ dangerouslyAllowBrowser: false','Assert the provider client is created only server-side.');
    if (node.type === 'NewExpression' && name(node.callee) === 'Function') emit(node,'inject-function','// Replace new Function(...) with a fixed function accepting typed data.','Assert unexpected operation names are rejected.');
    if (!call(node)) continue;
    const method = name(node.callee), receiver = rootName(node.callee), arg = node.arguments[0];
    if (server && method === 'getSession' && name(node.callee.object) === 'auth') {
      const root = receiver || 'supabase';
      emit(node,'auth-session-trust','- await ' + root + '.auth.getSession()\n+ await ' + root + '.auth.getUser()','Assert missing or invalid user identity is rejected before a side effect.');
    }
    if (method === 'eval' && (node.callee.type === 'Identifier' || ['window','globalThis'].includes(receiver))) emit(node,'inject-eval','// Replace eval with a fixed dispatcher or JSON.parse for JSON data.','Assert unrecognized input is rejected, not evaluated.');
    if (method === 'query' && arg?.type === 'TemplateLiteral' && arg.expressions.length) {
      const sql = arg.quasis.map((q: Node, i: number) => q.value.raw + (i < arg.expressions.length ? '$' + (i+1) : '')).join('');
      const values = arg.expressions.map((n: Node,i: number) => name(n) || 'value' + (i+1)).join(', ');
      emit(node,'inject-sql',(receiver || 'db') + '.query(' + JSON.stringify(sql) + ', [' + values + ']);','Assert SQL text is fixed and values are sent as parameters.','[Interpolated SQL omitted from report]');
    }
    if (method === '$queryRawUnsafe') emit(node,'inject-sql-raw','// Replace ' + (receiver || 'db') + '.$queryRawUnsafe with a parameterized ORM query.','Assert data is passed separately from SQL structure.');
    if ((shellFunctions.has(method) || (/^exec(?:Sync)?$/.test(method) && shellModules.has(receiver))) && arg?.type !== 'StringLiteral') emit(node,'inject-shell','// Use execFile(file, args) with an allowlisted executable and validated arguments.','Assert the executable is fixed and arguments are passed without a shell.','[Dynamic command omitted from report]');
    if (method === 'decode' && /^(?:jwt|jsonwebtoken)$/i.test(receiver) && !verifiedJwtBindings.has(name(arg))) emit(node,'auth-jwt-decode','- ' + receiver + '.decode(token)\n+ ' + receiver + '.verify(token, verificationKey, { algorithms: allowedAlgorithms })','Assert unsigned, expired or invalid tokens cannot authorize access.');
    if (method === 'redirect' && follows(arg,n => call(n) && name(n.callee) === 'get' && /searchParams/i.test(file.text.slice(n.start ?? 0,(n.start ?? 0)+70)))) emit(node,'inject-redirect','const allowed = new Set(["/", "/dashboard"]);\nredirect(typeof target === "string" && allowed.has(target) ? target : "/");','Assert external destinations are replaced with the internal fallback.');
    if (client && /create(?:Browser)?Client/.test(method) && follows(node,n => name(n) === 'SUPABASE_SERVICE_ROLE_KEY')) emit(node,'auth-client-service-role','// Initialize ' + method + ' with the browser-safe publishable key; keep privileged work server-side.','Assert the browser bundle never receives the service-role credential.');
    if (method === 'set' && /cookie/i.test(receiver) && node.arguments.length >= 2) {
      const options = node.arguments[2];
      if (!options || options.type === 'ObjectExpression') {
        if (objectValue(options,'httpOnly')?.value !== true) emit(node,'auth-cookie-http-only','// Set this cookie with { httpOnly: true } in its existing options.','Assert Set-Cookie includes HttpOnly.');
        if (!objectValue(options,'sameSite')) emit(node,'auth-cookie-same-site','// Set this cookie with { sameSite: "lax" } in its existing options.','Assert Set-Cookie includes SameSite=Lax.');
      }
    }
  }
  const origin = nodes.find(n => n.type === 'ObjectProperty' && name(n.key).toLowerCase() === 'access-control-allow-origin' && name(n.value) === '*');
  if (origin && nodes.some(n => n.type === 'ObjectProperty' && (name(n.key).toLowerCase() === 'access-control-allow-credentials' || name(n.key) === 'credentials') && (name(n.value) === 'true' || n.value?.value === true))) emit(origin,'auth-cors-credentials','- "Access-Control-Allow-Origin": "*"\n+ "Access-Control-Allow-Origin": trustedOrigin','Assert credentialed requests from untrusted origins receive no CORS authorization.');
  return { hits, skipped:false };
}
