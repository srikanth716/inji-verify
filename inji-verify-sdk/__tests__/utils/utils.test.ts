import { isDcApiSupported, isMobileDevice } from "../../src/utils/utils";
import { DC_API_PROTOCOL } from "../../src/utils/constants";

const DID_CLIENT_ID = "decentralized_identifier:did:web:example.com";

describe("isDcApiSupported", () => {
  const originalDigitalCredential = window.DigitalCredential;

  afterEach(() => {
    if (originalDigitalCredential === undefined) {
      delete (window as { DigitalCredential?: unknown }).DigitalCredential;
    } else {
      window.DigitalCredential = originalDigitalCredential;
    }
  });

  it("returns false when clientId is not a DID", () => {
    window.DigitalCredential = {
      userAgentAllowsProtocol: () => true,
    } as typeof DigitalCredential;

    expect(isDcApiSupported("pre_registered:client")).toBe(false);
  });

  it("returns false when DigitalCredential is missing", () => {
    delete (window as { DigitalCredential?: unknown }).DigitalCredential;
    expect(isDcApiSupported(DID_CLIENT_ID)).toBe(false);
  });

  it("returns true when DID clientId and protocol are allowed", () => {
    const allows = jest.fn((protocol: string) => protocol === DC_API_PROTOCOL);
    window.DigitalCredential = {
      userAgentAllowsProtocol: allows,
    } as typeof DigitalCredential;

    expect(isDcApiSupported(DID_CLIENT_ID)).toBe(true);
    expect(allows).toHaveBeenCalledWith(DC_API_PROTOCOL);
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
