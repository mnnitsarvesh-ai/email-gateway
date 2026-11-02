import type { ApiConfig } from '../../../config';

/** The platform's own DNS names that customers' records point at (D16). */
export interface GatewayDnsConfig {
  mxHosts: Array<{ priority: number; host: string }>;
  spfInclude: string;
  dmarcRua: string[];
  dmarcRuf: string[];
  verificationLabel: string;
}

export function gatewayDnsConfigFrom(
  config: Pick<
    ApiConfig,
    | 'GATEWAY_MX_HOSTS'
    | 'GATEWAY_SPF_INCLUDE'
    | 'GATEWAY_DMARC_RUA'
    | 'GATEWAY_DMARC_RUF'
    | 'DOMAIN_VERIFICATION_LABEL'
  >,
): GatewayDnsConfig {
  return {
    mxHosts: config.GATEWAY_MX_HOSTS.map((mx) => ({ priority: mx.priority, host: mx.host })),
    spfInclude: config.GATEWAY_SPF_INCLUDE,
    dmarcRua: [...config.GATEWAY_DMARC_RUA],
    dmarcRuf: [...config.GATEWAY_DMARC_RUF],
    verificationLabel: config.DOMAIN_VERIFICATION_LABEL,
  };
}
