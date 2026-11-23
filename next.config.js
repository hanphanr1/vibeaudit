const dev = process.env.NODE_ENV !== 'production';
const script = "script-src 'self' 'unsafe-inline'" + (dev ? " 'unsafe-eval'" : '');
const policy = ["default-src 'self'", script, "style-src 'self' 'unsafe-inline'", "img-src 'self' data:", "font-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "object-src 'none'"].join('; ');
module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: [
      { key: 'Content-Security-Policy', value: policy },
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'no-referrer' },
    ] }];
  },
};
