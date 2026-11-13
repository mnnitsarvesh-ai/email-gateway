import { Inject, Injectable } from '@nestjs/common';
import { generateWebhookSecret, secretAad, WebhookSecretCipher } from '@email-gateway/webhooks';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';

type Config = Pick<
  ApiConfig,
  'WEBHOOK_SECRET_ENCRYPTION_KEY' | 'WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS'
>;

export interface IssuedSecret {
  /** The plaintext `whsec_…` secret: returned once, never stored, logged or audited. */
  secret: string;
  /** `v1.<kid>.<iv>.<tag>.<ct>` bound to (organization, subscription, version). */
  ciphertext: string;
}

/**
 * Secret custody of the api (step 6.2 W7, §2.0 invariant 5): generates a signing secret with a
 * CSPRNG and encrypts it with `WEBHOOK_SECRET_ENCRYPTION_KEY` and the AAD of
 * `secretAad(organizationId, subscriptionPublicId, secretVersion)`. The api only encrypts; the
 * webhook-worker decrypts. Nothing here logs.
 */
@Injectable()
export class WebhookSecrets {
  private readonly cipher: WebhookSecretCipher;

  constructor(@Inject(API_CONFIG) config: Config) {
    this.cipher = WebhookSecretCipher.fromConfig(config);
  }

  issue(organizationId: bigint, subscriptionPublicId: string, secretVersion: number): IssuedSecret {
    const secret = generateWebhookSecret();
    return {
      secret,
      ciphertext: this.cipher.encrypt(
        secret,
        secretAad(organizationId, subscriptionPublicId, secretVersion),
      ),
    };
  }
}
