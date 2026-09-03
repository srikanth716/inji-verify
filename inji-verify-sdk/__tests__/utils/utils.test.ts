import {
  isDcApiSupported,
  isMobileDevice,
  isSignedRequestScheme,
  isChromeDcApiSecurityVersionMet,
  isDcqlVpToken,
  parseVpTokenFromFragment,
  extractVcFromVpToken,
  persistDatashareNonce,
  consumeDatashareNonce,
  verifyVpTokenBinding,
} from "../../src/utils/utils";
import { DC_API_PROTOCOL, DATASHARE_NONCE_STORAGE_KEY } from "../../src/utils/constants";

const DID_CLIENT_ID = "decentralized_identifier:did:web:example.com";
const X509_CLIENT_ID = "x509_san_dns:verify.example.com";
const CHROME_SECURE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.59 Safari/537.36";
const CHROME_INSECURE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.58 Safari/537.36";

describe("isSignedRequestScheme", () => {
  it("accepts DID and x509_san_dns client ids", () => {
    expect(isSignedRequestScheme(DID_CLIENT_ID)).toBe(true);
    expect(isSignedRequestScheme(X509_CLIENT_ID)).toBe(true);
  });

  it("rejects pre-registered and missing client ids", () => {
    expect(isSignedRequestScheme("pre_registered:client")).toBe(false);
    expect(isSignedRequestScheme("x509_san_dnsfoo")).toBe(false);
    expect(isSignedRequestScheme(undefined)).toBe(false);
  });
});

describe("isChromeDcApiSecurityVersionMet", () => {
  it("allows non-Chromium user agents", () => {
    expect(
      isChromeDcApiSecurityVersionMet(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      ),
    ).toBe(true);
  });

  it("rejects Chrome older than 144.0.7559.59", () => {
    expect(isChromeDcApiSecurityVersionMet(CHROME_INSECURE_UA)).toBe(false);
    expect(
      isChromeDcApiSecurityVersionMet(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
      ),
    ).toBe(false);
  });

  it("accepts Chrome 144.0.7559.59 and later", () => {
    expect(isChromeDcApiSecurityVersionMet(CHROME_SECURE_UA)).toBe(true);
    expect(
      isChromeDcApiSecurityVersionMet(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
      ),
    ).toBe(true);
  });
});

describe("isDcApiSupported", () => {
  const originalDigitalCredential = window.DigitalCredential;
  const originalUserAgent = navigator.userAgent;

  afterEach(() => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value: originalUserAgent,
    });
    if (originalDigitalCredential === undefined) {
      delete (window as { DigitalCredential?: unknown }).DigitalCredential;
    } else {
      window.DigitalCredential = originalDigitalCredential;
    }
  });

  const mockDcApi = () => {
    window.DigitalCredential = {
      userAgentAllowsProtocol: jest.fn((protocol: string) => protocol === DC_API_PROTOCOL),
    } as unknown as typeof DigitalCredential;
  };

  it("returns false when clientId is not a signed-request scheme", () => {
    mockDcApi();
    expect(isDcApiSupported("pre_registered:client")).toBe(false);
  });

  it("returns false when DigitalCredential is missing", () => {
    delete (window as { DigitalCredential?: unknown }).DigitalCredential;
    expect(isDcApiSupported(DID_CLIENT_ID)).toBe(false);
  });

  it("returns true when DID clientId and protocol are allowed", () => {
    mockDcApi();
    expect(isDcApiSupported(DID_CLIENT_ID)).toBe(true);
    expect(window.DigitalCredential.userAgentAllowsProtocol).toHaveBeenCalledWith(
      DC_API_PROTOCOL,
    );
  });

  it("returns true when x509_san_dns clientId and protocol are allowed", () => {
    mockDcApi();
    expect(isDcApiSupported(X509_CLIENT_ID)).toBe(true);
  });

  it("returns false on Chrome versions affected by CVE-2026-0904", () => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value: CHROME_INSECURE_UA,
    });
    mockDcApi();
    expect(isDcApiSupported(DID_CLIENT_ID)).toBe(false);
  });
});

describe("vp token redirect helpers", () => {
  it("detects DCQL vp_token shape", () => {
    expect(isDcqlVpToken({ "cred-id": [{}] })).toBe(true);
    expect(isDcqlVpToken({ verifiableCredential: [{}] })).toBe(false);
    expect(isDcqlVpToken(null)).toBe(false);
  });

  it("parses URL-encoded vp_token fragments", () => {
    const encoded = encodeURIComponent(
      JSON.stringify({ "cred-id": [{ type: ["VerifiableCredential"] }] })
    );
    expect(parseVpTokenFromFragment(encoded)).toEqual({
      "cred-id": [{ type: ["VerifiableCredential"] }],
    });
  });

  it("parses base64url vp_token fragments", () => {
    const json = JSON.stringify({
      verifiableCredential: [{ type: ["VerifiableCredential"] }],
    });
    const base64url = btoa(json)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(parseVpTokenFromFragment(base64url)).toEqual({
      verifiableCredential: [{ type: ["VerifiableCredential"] }],
    });
  });

  it("parses base64url vp_token fragments with non-ASCII claims", () => {
    const payload = {
      "cred-id": [
        {
          type: ["VerifiableCredential"],
          credentialSubject: { fullName: "José García", city: "München" },
        },
      ],
    };
    const json = JSON.stringify(payload);
    // Encode UTF-8 bytes to base64url without relying on TextEncoder in Jest.
    const utf8 = unescape(encodeURIComponent(json));
    const base64url = btoa(utf8)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    expect(parseVpTokenFromFragment(base64url)).toEqual(payload);
  });

  it("extracts a VC from DCQL vp_token", () => {
    const vc = {
      type: ["VerifiableCredential"],
      credentialSubject: { id: "1" },
    };
    expect(
      extractVcFromVpToken({
        "6426c84e-88af-4a6a-bd47-007ba549e3c9": [vc],
      })
    ).toEqual(vc);
  });

  it("extracts a VC nested in a presentation from DCQL vp_token", () => {
    const vc = { type: ["VerifiableCredential"] };
    expect(
      extractVcFromVpToken({
        query_id: [{ type: ["VerifiablePresentation"], verifiableCredential: [vc] }],
      })
    ).toEqual(vc);
  });

  it("extracts a VC from legacy PE vp_token", () => {
    const vc = { type: ["VerifiableCredential"] };
    expect(extractVcFromVpToken({ verifiableCredential: [vc] })).toEqual(vc);
  });
});

describe("datashare VP binding", () => {
  const clientId = "injiverify.qainji.mosip.net/";
  const nonce = "one-time-nonce-abc";

  const boundVp = {
    "cred-id": [
      {
        type: ["VerifiablePresentation"],
        verifiableCredential: [{ type: ["VerifiableCredential"] }],
        proof: { domain: clientId, challenge: nonce },
      },
    ],
  };

  afterEach(() => {
    sessionStorage.removeItem(DATASHARE_NONCE_STORAGE_KEY);
  });

  it("accepts a VP bound to clientId and nonce", () => {
    expect(() => verifyVpTokenBinding(boundVp, clientId, nonce)).not.toThrow();
  });

  it("rejects a VP with mismatched challenge", () => {
    expect(() =>
      verifyVpTokenBinding(boundVp, clientId, "other-nonce")
    ).toThrow(/challenge/);
  });

  it("rejects a VP with mismatched domain", () => {
    expect(() =>
      verifyVpTokenBinding(boundVp, "other-client/", nonce)
    ).toThrow(/domain/);
  });

  it("rejects a replayed VP after the datashare nonce is consumed", () => {
    persistDatashareNonce(nonce);
    const first = consumeDatashareNonce();
    expect(first).toBe(nonce);
    expect(() => verifyVpTokenBinding(boundVp, clientId, first!)).not.toThrow();

    const replayed = consumeDatashareNonce();
    expect(replayed).toBeNull();
    expect(() =>
      verifyVpTokenBinding(boundVp, clientId, replayed as unknown as string)
    ).toThrow(/Missing nonce/);
  });
});

describe("isMobileDevice", () => {
  const originalUserAgent = navigator.userAgent;

  afterEach(() => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value: originalUserAgent,
    });
  });

  it("detects iPhone user agents", () => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    });
    expect(isMobileDevice()).toBe(true);
  });

  it("does not treat desktop Chrome as mobile", () => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    });
    expect(isMobileDevice()).toBe(false);
  });
});
