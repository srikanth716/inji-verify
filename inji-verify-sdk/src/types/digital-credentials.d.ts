declare global {
  interface Window {
    DigitalCredential?: {
      userAgentAllowsProtocol?: (protocol: string) => boolean;
    };
  }
}

export {};
