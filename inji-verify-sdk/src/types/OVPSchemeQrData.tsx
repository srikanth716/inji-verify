export interface QrData {
  transactionId: string;
  requestId: string;
  authorizationDetails?: {
    responseType: string;
    responseMode: string;
    clientId: string;
    dcqlQuery: Record<string, unknown>;
    responseUri: string;
    nonce: string;
    iat: number;
  };
  expiresAt: number;
  requestUri?: string;
}
