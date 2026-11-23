import { rules, scanTarget } from '../engine';
import { ciWorkflow, thresholds, type Threshold } from '../engine/exporters';

const protocols = ['2025-11-25','2025-06-18','2025-03-26','2024-11-05'];
const tools = [
  { name:'vibeaudit_scan_path',description:'Read-only static security audit of a local source directory.',inputSchema:{type:'object',properties:{path:{type:'string',description:'Local filesystem directory; URLs are rejected.'}},required:['path'],additionalProperties:false} },
  { name:'vibeaudit_list_rules',description:'List deterministic rule metadata and risk descriptions.',inputSchema:{type:'object',properties:{},additionalProperties:false} },
  { name:'vibeaudit_generate_ci',description:'Generate a CI workflow with a severity threshold.',inputSchema:{type:'object',properties:{threshold:{type:'string',enum:thresholds}},required:['threshold'],additionalProperties:false} },
];

function record(value: unknown): value is Record<string,unknown> {
  return !!value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}

export function createRpcSession() {
  let state: 'new' | 'negotiated' | 'ready' = 'new';
  return async function rpc(message: unknown) {
  const jsonrpc = '2.0';
  const invalid = { jsonrpc,id:null,error:{code:-32600,message:'Invalid request'} };
  if (!record(message) || message.jsonrpc !== jsonrpc || typeof message.method !== 'string') return invalid;
  const {id,method,params} = message;
  if (!('id' in message)) {
    if (!method.startsWith('notifications/')) return invalid;
    if (method === 'notifications/initialized' && state === 'negotiated') state = 'ready';
    return;
  }
  if (typeof id !== 'string' && !Number.isInteger(id)) return invalid;
  const result = (value: unknown) => ({jsonrpc,id,result:value});
  const error = (code: number, message: string) => ({jsonrpc,id,error:{code,message}});
  if (method === 'initialize') {
    if (state !== 'new') return error(-32600,'Server already initialized');
    if (!record(params) || typeof params.protocolVersion !== 'string' || !params.protocolVersion.trim() || !record(params.capabilities) || !record(params.clientInfo) || typeof params.clientInfo.name !== 'string' || !params.clientInfo.name.trim() || typeof params.clientInfo.version !== 'string' || !params.clientInfo.version.trim()) return error(-32602,'Invalid initialize parameters');
    const requested = params.protocolVersion;
    state = 'negotiated';
    return result({protocolVersion:protocols.includes(requested) ? requested : protocols[0],capabilities:{tools:{}},serverInfo:{name:'vibeaudit',version:'0.1.0'}});
  }
  if (method === 'ping') return result({});
  if ((method === 'tools/list' || method === 'tools/call') && state !== 'ready') return error(-32002,'Server not initialized');
  if (method === 'tools/list') return result({ tools });
  if (method !== 'tools/call') return error(-32601,'Method not found');
  if (!record(params) || typeof params.name !== 'string' || (params.arguments !== undefined && !record(params.arguments))) return error(-32602,'Invalid tool arguments');
  if (!tools.some(tool => tool.name === params.name)) return error(-32602,'Unknown tool');
  const args = params.arguments ?? {};
  const content = (text: string, isError = false) => result({ content:[{type:'text',text}],isError });
  try {
    if (params.name === 'vibeaudit_list_rules') {
      if (Object.keys(args).length) return content('This tool accepts no arguments.',true);
      return content(JSON.stringify(rules));
    }
    if (params.name === 'vibeaudit_generate_ci') {
      if (Object.keys(args).length !== 1 || !thresholds.includes(args.threshold as Threshold)) return content('Choose a valid threshold.',true);
      return content(ciWorkflow(args.threshold as Threshold));
    }
    if (Object.keys(args).length !== 1 || typeof args.path !== 'string' || !args.path.trim() || args.path.length > 4096 || /^[a-z][\w+.-]*:\/\//i.test(args.path) || args.path.startsWith('git@')) return content('Provide a valid local directory, not a URL.',true);
    return content(JSON.stringify(await scanTarget(args.path)));
  } catch (error) { return content(error instanceof Error ? error.message : 'Scan failed.',true); }
  };
}

export async function startStdio() {
  const rpc = createRpcSession();
  process.stdin.setEncoding('utf8');
  const write = (object: unknown) => new Promise<void>((resolve, reject) => {
    process.stdout.write(JSON.stringify(object) + '\n', error => error ? reject(error) : resolve());
  });
  const parseError = {jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid or oversized JSON frame'}};
  let frame = '', discard = false;
  for await (const chunk of process.stdin as AsyncIterable<string>) {
    const segments = chunk.split('\n');
    for (const [i,part] of segments.entries()) {
      if (!discard) {
        if (frame.length + part.length > 64 * 1024) { discard = true; frame = ''; }
        else frame += part;
      }
      if (i === segments.length - 1) continue;
      if (discard) await write(parseError);
      else if (frame.trim()) {
        let parsed: unknown;
        try { parsed = JSON.parse(frame); } catch { await write(parseError); frame = ''; continue; }
        const response = await rpc(parsed);
        if (response) await write(response);
      }
      frame = ''; discard = false;
    }
  }
}
