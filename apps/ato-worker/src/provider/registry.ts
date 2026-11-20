import { ProviderRegistry, type IdentityProviderAdapter } from '@email-gateway/ato-detection';
import { FakeIdentityProviderAdapter } from '@email-gateway/ato-detection/fake-provider';
import type { AtoProviderIntegration } from '@email-gateway/database';

/**
 * The identity-provider registry of the worker (D15). Step 8.5 registers the Microsoft Entra ID
 * and Google Workspace factories bound per integration (PX2, `IdpRuntime.register`) where a
 * provider-calling role runs. The fake adapter is
 * registered only with `ATO_PROVIDER_FAKE_ENABLED=true` and `APP_ENV` in {local, ci}; the config
 * schema and `ProviderRegistry.registerFake` both refuse it elsewhere. It never calls any real
 * identity provider.
 */
export function createProviderRegistry(
  config: { APP_ENV: string; ATO_PROVIDER_FAKE_ENABLED: boolean },
  fake?: IdentityProviderAdapter,
): ProviderRegistry<AtoProviderIntegration> {
  const registry = new ProviderRegistry<AtoProviderIntegration>();
  if (!config.ATO_PROVIDER_FAKE_ENABLED) return registry;
  return registry.registerFake(fake ?? new FakeIdentityProviderAdapter(), {
    enabled: true,
    appEnv: config.APP_ENV,
  });
}
