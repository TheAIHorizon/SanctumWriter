/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Enable standalone output for Docker
  output: 'standalone',
  // Note: no CORS headers are set for /api/* on purpose. The API is
  // same-origin only; a wildcard Access-Control-Allow-Origin would let any
  // website drive the local file APIs from the user's browser.
};

module.exports = nextConfig;












