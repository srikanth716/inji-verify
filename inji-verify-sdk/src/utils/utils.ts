import {VALID_SD_JWT_TYPES, DC_API_PROTOCOL, DEFAULT_DC_API_TIMEOUT_MS, CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER, CLIENT_ID_PREFIX_X509_SAN_DNS, CLIENT_ID_PREFIX_REDIRECT_URI, MIN_CHROME_DC_API_VERSION, DATASHARE_NONCE_STORAGE_KEY} from "./constants";
import {CredentialResult, VCVerificationV2Response} from "../components/qrcode-verification/QRCodeVerification.types";

/** Max delay accepted by `window.setTimeout` (signed 32-bit int). */
const MAX_SET_TIMEOUT_MS = 2_147_483_647;

/** Finite positive ms, floored, at least 1ms, and capped; otherwise the 5-minute default. */
export const normalizeDcApiTimeoutMs = (value: number | undefined): number => {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return DEFAULT_DC_API_TIMEOUT_MS;
  }
  return Math.min(Math.max(Math.floor(value), 1), MAX_SET_TIMEOUT_MS);
};

export const isMobileDevice = (): boolean => {
  const userAgent = navigator.userAgent;

  const isMobileUA = /Android.*Mobile|iPhone|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    userAgent
  );

  const isTabletUA =
    /iPad/i.test(userAgent) ||
    (/Macintosh/i.test(userAgent) && "ontouchend" in document) || // iPad iOS13+ (real)
    (/Android/i.test(userAgent) && !/Mobile/i.test(userAgent)); // Android tablet

  return isMobileUA || isTabletUA;
};

export const isSignedRequestScheme = (clientId?: string): boolean =>
  typeof clientId === "string" &&
  (clientId.startsWith(`${CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER}:`) ||
    clientId.startsWith(`${CLIENT_ID_PREFIX_X509_SAN_DNS}:`));

export const isRedirectUriClientId = (clientId?: string): boolean =>
  typeof clientId === "string" &&
  clientId.startsWith(`${CLIENT_ID_PREFIX_REDIRECT_URI}:`);

/** Parse Chrome/CriOS version; null when the UA is not Chromium-based. */
const parseChromiumVersion = (userAgent: string): number[] | null => {
  const match = userAgent.match(/(?:Chrome|CriOS)\/(\d+)(?:\.(\d+)\.(\d+)\.(\d+))?/);
  if (!match) return null;
  return [
    Number(match[1]),
    Number(match[2] || 0),
    Number(match[3] || 0),
    Number(match[4] || 0),
  ];
};

/**
 * Chrome versions before 144.0.7559.59 are affected by CVE-2026-0904
 * (Digital Credentials UI domain spoofing). Non-Chromium UAs skip this gate.
 */
export const isChromeDcApiSecurityVersionMet = (
  userAgent: string = navigator.userAgent,
): boolean => {
  const version = parseChromiumVersion(userAgent);
  if (version === null) return true;
  for (let i = 0; i < MIN_CHROME_DC_API_VERSION.length; i++) {
    if (version[i] > MIN_CHROME_DC_API_VERSION[i]) return true;
    if (version[i] < MIN_CHROME_DC_API_VERSION[i]) return false;
  }
  return true;
};

export const isDcApiSupported = (clientId: string): boolean => {
  if (!isSignedRequestScheme(clientId)) return false;
  if (!isChromeDcApiSecurityVersionMet()) return false;
  if (typeof window.DigitalCredential === "undefined") return false;
  const allows = window.DigitalCredential.userAgentAllowsProtocol;
  if (typeof allows !== "function") return false;
  return allows.call(window.DigitalCredential, DC_API_PROTOCOL) === true;
};

export const isSdJwt = (vpToken: string): boolean => {
    try {
        const jwtParts = vpToken.split('~')[0].split('.');
        if (jwtParts.length !== 3) {
            return false;
        }
        const header = decodeBase64Url(jwtParts[0]);
        const {typ} = JSON.parse(header);
        return VALID_SD_JWT_TYPES.has(typ);
    }catch (e) {
        console.log("Invalid SD-JWT:", e);
        return false;
    }
}


const decodeBase64Url = (encoded: string): string => {
    let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    if (pad) base64 += "=".repeat(4 - pad);
    const decoded = atob(base64);
    const decodedBytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(decodedBytes);
};

/**
 * OpenID4VP 1.0 DCQL vp_token: object keyed by credential query id,
 * each value an array of presentations/credentials.
 * Legacy PE shape has a top-level `verifiableCredential` array instead.
 */
export const isDcqlVpToken = (vpToken: unknown): vpToken is Record<string, unknown[]> => {
  if (!vpToken || typeof vpToken !== "object" || Array.isArray(vpToken)) {
    return false;
  }
  if ("verifiableCredential" in (vpToken as object)) {
    return false;
  }
  const entries = Object.entries(vpToken as Record<string, unknown>);
  return (
    entries.length > 0 &&
    entries.every(([, value]) => Array.isArray(value))
  );
};

/**
 * Parse vp_token from a redirect hash fragment.
 * Supports base64url (legacy) and URL-decoded / plain JSON (OpenID4VP 1.0).
 */
export const parseVpTokenFromFragment = (vpTokenParam: string): unknown => {
  try {
    return JSON.parse(decodeBase64Url(vpTokenParam));
  } catch {
    try {
      return JSON.parse(decodeURIComponent(vpTokenParam));
    } catch {
      return JSON.parse(vpTokenParam);
    }
  }
};

/**
 * Extract a single VC from either a legacy PE vp_token or an OpenID4VP 1.0 DCQL vp_token.
 */
export const extractVcFromVpToken = (vpToken: unknown): unknown => {
  if (!vpToken || typeof vpToken !== "object") {
    throw new Error("Invalid vp_token in redirect URL");
  }

  if ("verifiableCredential" in (vpToken as object)) {
    const vcs = (vpToken as { verifiableCredential?: unknown[] })
      .verifiableCredential;
    if (!Array.isArray(vcs) || !vcs.length) {
      throw new Error("Missing verifiableCredential in vp_token");
    }
    return vcs[0];
  }

  if (isDcqlVpToken(vpToken)) {
    const presentations = Object.values(vpToken)[0];
    if (!presentations?.length) {
      throw new Error("Empty credential entry in vp_token");
    }
    const presentation = presentations[0];
    if (
      presentation &&
      typeof presentation === "object" &&
      "verifiableCredential" in presentation
    ) {
      const nested = (presentation as { verifiableCredential?: unknown[] })
        .verifiableCredential;
      if (Array.isArray(nested) && nested.length) {
        return nested[0];
      }
    }
    // DCQL ldp_vc: credential object is the presentation entry itself
    return presentation;
  }

  throw new Error("Unsupported vp_token format in redirect URL");
};

const normalizeTypeList = (type: unknown): string[] => {
  if (typeof type === "string") return [type];
  if (Array.isArray(type)) {
    return type.filter((t): t is string => typeof t === "string");
  }
  return [];
};

const audienceMatches = (expected: string, actual: unknown): boolean => {
  if (typeof actual !== "string" || !actual) return false;
  const normalize = (value: string) => {
    let end = value.length;
    while (end > 0 && value.charAt(end - 1) === "/") end--;
    return value.slice(0, end);
  };
  return normalize(expected) === normalize(actual);
};

const collectPresentations = (vpToken: unknown): unknown[] => {
  if (!vpToken || typeof vpToken !== "object") {
    return [];
  }
  if (isDcqlVpToken(vpToken)) {
    return Object.values(vpToken).flat();
  }
  // Legacy PE: treat the whole object as one presentation
  return [vpToken];
};

const verifySdJwtBinding = (sdJwt: string, clientId: string, nonce: string): void => {
  const parts = sdJwt.split("~");
  const kbJwt = parts[parts.length - 1];
  if (!kbJwt || kbJwt.split(".").length !== 3) {
    throw new Error("SD-JWT is missing Key Binding JWT for VP binding validation");
  }
  const payload = JSON.parse(decodeBase64Url(kbJwt.split(".")[1]));
  if (!audienceMatches(clientId, payload.aud)) {
    throw new Error("KB-JWT aud does not match client_id");
  }
  if (payload.nonce !== nonce) {
    throw new Error("KB-JWT nonce does not match expected nonce");
  }
};

/**
 * Persist a one-time nonce for the datashare (`!isVPSubmissionSupported`) redirect flow.
 */
export const persistDatashareNonce = (nonce: string): void => {
  sessionStorage.setItem(DATASHARE_NONCE_STORAGE_KEY, nonce);
};

/**
 * Read and remove the datashare nonce. Returns null if missing (already consumed / never set).
 */
export const consumeDatashareNonce = (): string | null => {
  const nonce = sessionStorage.getItem(DATASHARE_NONCE_STORAGE_KEY);
  if (nonce != null) {
    sessionStorage.removeItem(DATASHARE_NONCE_STORAGE_KEY);
  }
  return nonce;
};

/**
 * Validate holder binding for presentations in a redirect `vp_token`
 * against the expected `client_id` and one-time `nonce`.
 *
 * LDP VPs: `proof.domain` / `proof.challenge`
 * SD-JWT: KB-JWT `aud` / `nonce`
 * Bare VCs (no VP wrapper): no proof to check; session nonce still prevents replay.
 */
export const verifyVpTokenBinding = (vpToken: unknown, clientId: string, nonce: string): void => {
  if (!nonce) {
    throw new Error("Missing nonce for VP binding validation");
  }
  if (!clientId) {
    throw new Error("Missing clientId for VP binding validation");
  }

  const presentations = collectPresentations(vpToken);
  if (!presentations.length) {
    throw new Error("No presentations found in vp_token");
  }

  for (const presentation of presentations) {
    if (typeof presentation === "string") {
      if (isSdJwt(presentation)) {
        verifySdJwtBinding(presentation, clientId, nonce);
      }
      continue;
    }

    if (!presentation || typeof presentation !== "object") {
      throw new Error("Invalid presentation in vp_token");
    }

    const record = presentation as Record<string, unknown>;
    const types = normalizeTypeList(record.type);
    const proof =
      record.proof && typeof record.proof === "object"
        ? (record.proof as Record<string, unknown>)
        : null;
    const isVp =
      types.includes("VerifiablePresentation") ||
      (proof != null && ("challenge" in proof || "domain" in proof));

    if (!isVp) {
      continue;
    }

    if (!proof) {
      throw new Error("VP is missing proof for binding validation");
    }
    if (!audienceMatches(clientId, proof.domain)) {
      throw new Error("VP proof.domain does not match client_id");
    }
    if (proof.challenge !== nonce) {
      throw new Error("VP proof.challenge does not match nonce");
    }
  }
};

export const normalizeVp = (vp: any): Record<string, unknown> => {
    if (typeof vp === "string") {
        if (isSdJwt(vp)) vp ;
        try {
            return JSON.parse(vp);
        } catch {
           {vp};
        }
    }
    return vp;
};

export const clearUrl = (params: string[] = []) => {
    const url = new URL(window.location.href);

    const hashParamsObj = new URLSearchParams(url.hash.slice(1));
    params.forEach(param => {
        url.searchParams.delete(param);
        hashParamsObj.delete(param);
    });
    url.hash = hashParamsObj.toString()
      ? `#${hashParamsObj.toString()}`
      : "";

    window.history.replaceState(null, "", url.pathname + url.search + url.hash);
};

export const summariseVCResult = (
    response: VCVerificationV2Response
): "SUCCESS" | "INVALID" | "EXPIRED" | "REVOKED" => {

    if (!response.schemaAndSignatureCheck?.valid) {
        return "INVALID";
    }

    if (!response.expiryCheck?.valid) {
        return "EXPIRED";
    }

    if (response.statusCheck?.length) {
        for (const status of response.statusCheck) {
            if (status.error) {
                throw new Error(
                    status.error.errorMessage || "Status check error occurred"
                );
            }

            const isRevoked =
                status.purpose === "revocation" &&
                !status.valid &&
                status.error == null;

            if (isRevoked) return "REVOKED";
        }
    }

    return response.allChecksSuccessful ? "SUCCESS" : "INVALID";
};
export const summariseVPResult = (cred: CredentialResult): "SUCCESS" | "INVALID" | "EXPIRED" | "REVOKED" => {
    if (cred.holderProofCheck?.valid === false) return "INVALID";

    if (cred.schemaAndSignatureCheck?.valid === false) return "INVALID";

    if (cred.expiryCheck?.valid === false) return "EXPIRED";

    if (cred.statusCheck?.length) {
        for (const status of cred.statusCheck) {
            if (status.error) {
                throw new Error(status.error.errorMessage || "Status check error occurred");}

            const isRevoked =
                status.purpose === "revocation" &&
                    status.valid === false &&
                status.error == null;

            if (isRevoked) return "REVOKED";
        }
    }

    return cred.allChecksSuccessful ? "SUCCESS" : "INVALID";
};
