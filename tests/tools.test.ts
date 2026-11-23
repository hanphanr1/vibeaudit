import { expect, test } from 'vitest';
import { runCli } from '../src/tools/cli';
import { createRpcSession } from '../src/tools/mcp';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ciWorkflow } from '../src/engine/exporters';

test('CLI rejects invalid arguments and enforces the selected severity threshold', async () => {
  const lines: string[] = [];
  const write = (line: string) => { lines.push(line); };
  expect(await runCli(['scan'],write,write)).toBe(2);
  expect(await runCli(['scan','fixtures/vulnerable-vibe-app','--json','--fail-on','high'],write,write)).toBe(1);
  expect(JSON.parse(lines.at(-1)!).findings.some((f: { severity: string }) => f.severity === 'critical')).toBe(true);
  expect(await runCli(['scan','fixtures/hardened-near-miss-app','--fail-on','low'],write,write)).toBe(0);
});

test('MCP lists actual tools, denies a network scan, and returns deterministic CI YAML', async () => {
  const rpc = createRpcSession();
  const send = (method: string, params?: unknown) => rpc({ jsonrpc:'2.0',id:7,method,params });
  expect(await send('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'1.0'}})).toMatchObject({ id:7,result:{ protocolVersion:'2025-03-26',capabilities:{tools:{}} } });
  expect(await send('tools/list')).toMatchObject({error:{code:-32002}});
  await rpc({jsonrpc:'2.0',method:'notifications/initialized'});
  expect(await send('tools/list')).toMatchObject({ result:{ tools:[{name:'vibeaudit_scan_path'},{name:'vibeaudit_list_rules'},{name:'vibeaudit_generate_ci'}] } });
  expect(await send('tools/call',{name:'vibeaudit_scan_path',arguments:{path:'https://github.com/a/b'}})).toMatchObject({ result:{isError:true} });
  const response = await send('tools/call',{name:'vibeaudit_generate_ci',arguments:{threshold:'low'}});
  expect(JSON.stringify(response)).toContain('--fail-on low');
});

test('partial parse results never pass an enabled CLI threshold', async () => {
  const root = await mkdtemp(join(tmpdir(),'vibeaudit-partial-'));
  try {
    await writeFile(join(root,'broken.ts'),'const data = ;');
    const out: string[] = [], err: string[] = [];
    expect(await runCli(['scan',root,'--sarif','--fail-on','high'],s => out.push(s),s => err.push(s))).toBe(1);
    expect(err.join(' ')).toMatch(/incomplete.*parse/i);
    expect(JSON.parse(out[0]).runs[0].invocations[0]).toMatchObject({executionSuccessful:false,toolExecutionNotifications:[{level:'warning'}]});
    expect(await runCli(['scan',root,'--fail-on','none'],() => {},() => {})).toBe(0);
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('generated CI cannot execute the scanner without a reviewed commit', () => {
  const workflow = ciWorkflow('high');
  expect(workflow).toMatch(/actions\/checkout@[a-f0-9]{40} # v4/);
  expect(workflow).toMatch(/actions\/setup-node@[a-f0-9]{40} # v4/);
  expect(workflow).toContain('<PINNED_COMMIT_SHA>');
  expect(workflow).not.toMatch(/git clone/);
});

test('MCP rejects invalid IDs, invalid initialization, and tools before the handshake', async () => {
  const rpc = createRpcSession();
  expect(await rpc({jsonrpc:'2.0',id:1.5,method:'ping'})).toMatchObject({id:null,error:{code:-32600}});
  const init = {protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test'}};
  for (const id of [null,undefined,false,{}]) expect(await rpc({jsonrpc:'2.0',id,method:'initialize',params:init})).toMatchObject({id:null,error:{code:-32600}});
  expect(await rpc({jsonrpc:'2.0',method:'tools/list'})).toMatchObject({id:null,error:{code:-32600}});
  expect(await rpc({jsonrpc:'2.0',id:0,method:'initialize',params:init})).toMatchObject({id:0,error:{code:-32602}});
  await rpc({jsonrpc:'2.0',method:'notifications/initialized'});
  for (const method of ['tools/list','tools/call']) expect(await rpc({jsonrpc:'2.0',id:'early',method})).toMatchObject({id:'early',error:{code:-32002}});
});
