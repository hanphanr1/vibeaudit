const { createServer } = require('node:http');
process.env.NEXT_TELEMETRY_DISABLED = '1';
const next = require('next');
const hostname = '127.0.0.1';
const port = Number(process.env.PORT ?? '3000');
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
const app = next({ dev: process.argv.includes('--dev'), hostname, port });
app.prepare().then(() => {
  createServer(app.getRequestHandler()).listen(port, hostname, () => {
    console.log('VibeAudit: http://' + hostname + ':' + port);
  });
}).catch(error => { console.error(error.message); process.exitCode = 1; });
