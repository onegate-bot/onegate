// Tests run entirely against local stub servers. Strip any ambient proxy
// configuration (NODE_USE_ENV_PROXY makes node:http honor these) so client
// connections in tests reach 127.0.0.1 directly instead of a corporate proxy.
for (const key of [
  "NODE_USE_ENV_PROXY",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "http_proxy",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
]) {
  delete process.env[key];
}
