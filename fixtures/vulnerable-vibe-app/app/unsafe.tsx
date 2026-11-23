'use client';
import { exec } from 'node:child_process';
export function Example({ html }: { html: string }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }
export function sample(query: string, token: string, request: URL) {
  db.query(`SELECT id FROM orders WHERE id = ${query}`);
  db.$queryRawUnsafe(query);
  eval(query);
  new Function(query);
  exec(`synthetic-tool ${query}`);
  jwt.decode(token);
  cookies.set('session',token,{});
  redirect(request.searchParams.get('returnTo'));
  createClient(url,process.env.SUPABASE_SERVICE_ROLE_KEY);
  return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' };
}
