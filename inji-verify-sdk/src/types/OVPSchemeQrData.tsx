export interface QrData {
  transactionId: string;
  requestId: string;
  authorizationDetails?: {
    responseType: string;
    responseMode: string;
    clientId: string;
    dcqlQuery: unknown;
    responseUri: string;
    nonce: string;
    iat: number;
    verifierInfo?: {
      organization_name?: string;
      policy_uri?: string;
      attestations?: Array<{
        type?: string;
        issuer?: string;
        credential?: string;
      }>;
    };
  };
  expiresAt: number;
  requestUri?: string;
}