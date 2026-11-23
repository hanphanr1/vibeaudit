import { execFile } from 'node:child_process';
export function Example({ html }: { html: string }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />; }
export function sample(value: string, token: string, request: URL) {
  db.query('SELECT id FROM orders WHERE id = $1', [value]);
  execFile('synthetic-tool',['--',value]);
  jwt.verify(token,publicKey,{algorithms:['RS256']});
  cookies.set('session',token,{httpOnly:true,sameSite:'lax'});
  const next = request.searchParams.get('returnTo');
  redirect(next === '/orders' ? next : '/');
  return { 'Access-Control-Allow-Origin': 'https://example.invalid', 'Access-Control-Allow-Credentials': 'true' };
}
