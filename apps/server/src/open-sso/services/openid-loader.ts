import type * as OpenIdClientType from 'openid-client';

export type OpenIdClientModule = typeof OpenIdClientType;

let cachedClient: OpenIdClientModule | null = null;

export async function loadOpenIdClient(): Promise<OpenIdClientModule> {
  if (cachedClient) {
    return cachedClient;
  }
  // Load Pure-ESM openid-client dynamically in CommonJS environment
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const importFn = new Function('specifier', 'return import(specifier)');
  const mod = await importFn('openid-client');
  cachedClient = mod as OpenIdClientModule;
  return cachedClient;
}

export function setOpenIdClientForTesting(mock: OpenIdClientModule | null) {
  cachedClient = mock;
}
