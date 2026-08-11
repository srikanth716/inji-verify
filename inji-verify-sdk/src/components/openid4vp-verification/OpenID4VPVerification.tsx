import "./OpenID4VPVerification.css";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  AppError,
  SessionState,
  OpenID4VPVerificationProps,
  VerificationResults,
  CredentialResult
} from "./OpenID4VPVerification.types";
import {
  vpRequestStatus,
  vpSessionRequest,
  vpSessionResults,
  getVpRequestJwt,
  isAppError,
} from "../../utils/api";
import {clearUrl, summariseVPResult, normalizeVp, isDcApiSupported, isMobileDevice, normalizeDcApiTimeoutMs} from "../../utils/utils";
import { QrData } from "../../types/OVPSchemeQrData";
import { DC_API_PROTOCOL, DEFAULT_DC_API_TIMEOUT_MS } from "../../utils/constants";

const OpenID4VPVerification: React.FC<OpenID4VPVerificationProps> = ({
  triggerElement,
  verifyServiceUrl,
  protocol,
  dcqlQuery,
  transactionId,
  onVPReceived,
  onVPProcessed,
  qrCodeStyles,
  onQrCodeExpired,
  onError,
  clientId,
  isSameDeviceFlowEnabled = true,
  enableDcApi = true,
  dcApiTimeoutMs = DEFAULT_DC_API_TIMEOUT_MS,
  webWalletBaseUrl,
  vpVerificationRequest,
  summariseResults = true
}) => {
  const [qrCodeData, setQrCodeData] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const isActiveRef = useRef(false);
  const redirectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasFetchedVPResultRef = useRef(false);
  const sessionStateRef = useRef<SessionState>({requestId: ""});

  const shouldShowQRCode = !loading && qrCodeData;

  const DEFAULT_PROTOCOL = "openid4vp://";

  const VPFormatsSupported = useMemo(
    () => ({
      ldp_vp: {
        proof_type: [
          "Ed25519Signature2018",
          "Ed25519Signature2020",
          "RsaSignature2018",
        ],
      },
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
        "kb-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
      },
      "vc+sd-jwt": {
        "sd-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
        "kb-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
      },
    }),
    []
  );

  const clearSessionData = useCallback(() => {
    sessionStateRef.current = {
      requestId: "",
    };
  }, []);

  const resetState = useCallback(() => {
    if (redirectTimeoutRef.current) {
      clearTimeout(redirectTimeoutRef.current);
      redirectTimeoutRef.current = null;
    }
    setQrCodeData(null);
    setLoading(false);
    isActiveRef.current = false;
    hasFetchedVPResultRef.current = false;
    clearSessionData();
  }, [clearSessionData]);

  const isDcApiSession = useCallback(
    () => sessionStateRef.current.flow === "dc_api",
    []
  );

  const getPresentationDefinitionParams = useCallback(
    (data: QrData) => {
      const params = new URLSearchParams();
      params.set("client_id", clientId);
      if (data.requestUri) {
        params.set("request_uri", data.requestUri);
      } else if (data.authorizationDetails) {
        params.set("state", data.requestId);
        params.set("response_mode", data.authorizationDetails.responseMode);
        params.set("response_type", data.authorizationDetails.responseType);
        params.set("nonce", data.authorizationDetails.nonce);
        params.set("response_uri", data.authorizationDetails.responseUri);
        if (data.authorizationDetails.dcqlQuery) {
          params.set("dcql_query", JSON.stringify(data.authorizationDetails.dcqlQuery));
        }
        if(clientId.startsWith("decentralized_identifier:") || clientId.startsWith("redirect_uri:")) {
          params.set(
            "client_metadata",
            JSON.stringify({
              vp_formats_supported: VPFormatsSupported,
            })
          );
        }
      }
      return params.toString();
    },
    [clientId]
  );

  const processVPResultResponse = useCallback(
      (response: {
            credentialResults?: CredentialResult[];
            transactionId?: string;
        }) => {
            const credentialResults = response.credentialResults ?? [];

            if (onVPProcessed) {
                if (summariseResults) {
                    const vcResults = credentialResults.map((cred) => {
                        const vc = normalizeVp(cred.verifiableCredential);
                        const vcStatus = summariseVPResult(cred);
                        return { vc, vcStatus };
                    });

                    const vpResultStatus = credentialResults.length > 0 &&
                    credentialResults.every((c: CredentialResult) => c.allChecksSuccessful)
                        ? "SUCCESS" : "INVALID";

                    const result: VerificationResults = vcResults.map(v => ({
                        vc: v.vc,
                        verificationResponse: {
                            vcResults,
                            vpResultStatus,
                        },
                    }));

                    onVPProcessed(result);
                } else {
                    const VPResult: VerificationResults = credentialResults.map(
                        (cred: CredentialResult) => ({
                            vc: normalizeVp(cred.verifiableCredential),
                            verificationResponse: cred,
                        }),
                    );
                    onVPProcessed(VPResult);}
            } else if (onVPReceived && response.transactionId) {
                onVPReceived(response.transactionId);
            }
        },
        [onVPProcessed, onVPReceived, summariseResults]
    );
  const fetchVPResult = useCallback(
    async (responseCode?: string | null) => {
      if (!isActiveRef.current) return;
      setLoading(true);

      try {
        const response = await vpSessionResults(
          verifyServiceUrl,
          responseCode,
          vpVerificationRequest,
        );

        if (!response) {
          throw new Error(
            "An unexpected error occurred while processing the VP session result. Empty response.",
          );
        }

        processVPResultResponse(response);
        resetState();
      } catch (error) {
        if (isActiveRef.current) {
          onError(error as AppError);
          resetState();
        }
      } finally {
        clearUrl(["response_code"]);
      }
    },
    [verifyServiceUrl, onVPProcessed, onVPReceived, onError, vpVerificationRequest]
  );

  const fetchVPStatus = useCallback(
    async (reqId: string) => {
      if (!isActiveRef.current || isDcApiSession()) return;

      try {
        const response = await vpRequestStatus(verifyServiceUrl, reqId);

        if (!isActiveRef.current || isDcApiSession()) return;

        if (response.status === "ACTIVE") {
            fetchVPStatus(reqId);
        } else if (response.status === "VP_SUBMITTED") {
          fetchVPResult();
        } else if (response.status === "EXPIRED") {
          resetState();
          onQrCodeExpired();
        }
      } catch (error) {
        if (isActiveRef.current) {
          setLoading(false);
          resetState();
          onError(error as AppError);
        }
      }
    },
    [
      verifyServiceUrl,
      onQrCodeExpired,
      fetchVPResult,
      isDcApiSession,
      resetState,
      onError,
    ]
  );

  const createVPRequest = useCallback(async (isCrossDeviceFlow: boolean, responseMode?: "direct_post" | "dc_api") => {
    if (isActiveRef.current) return;
    isActiveRef.current = true;
    setLoading(true);
    try {
      const responseCodeValidationRequired = webWalletBaseUrl != null && responseMode !== "dc_api";

      const data = await vpSessionRequest(
        verifyServiceUrl,
        dcqlQuery,
        clientId,
        transactionId ?? undefined,
        responseCodeValidationRequired,
        responseMode,
      );

      if (webWalletBaseUrl == null && !isCrossDeviceFlow && responseMode !== "dc_api") {
        sessionStateRef.current = {
          requestId: data.requestId,
          flow: "openid4vp",
        };
      }
      if (isCrossDeviceFlow) {
        sessionStateRef.current = {
          requestId: data.requestId,
          flow: "openid4vp",
        };
        fetchVPStatus(data.requestId);
      }
      return data;
    } catch (error) {
      onError(error as AppError);
      resetState();
    }
  }, [
    verifyServiceUrl,
    transactionId,
    dcqlQuery,
    onError,
    clientId,
    webWalletBaseUrl,
    fetchVPStatus,
    resetState,
  ]);

  const handleTriggerClick = () => {
    if (isSameDeviceFlowEnabled) {
      startVerification();
    } else {
      handleGenerateQRCode();
    }
  };

  const handleGenerateQRCode = async () => {
    const data = await createVPRequest(true, "direct_post");
    if (data) {
      const pdParams = getPresentationDefinitionParams(data);
      const qrData = `${protocol || DEFAULT_PROTOCOL}authorize?${pdParams}`;
      setQrCodeData(qrData);
      setLoading(false);
    }
  };

  const startDcApiVerification = async () => {
    const data = await createVPRequest(false, "dc_api");
    if (!data) return;

    sessionStateRef.current = { requestId: data.requestId, flow: "dc_api", submissionUri: data.submissionUri};

    const controller = new AbortController();
    const timeoutMs = normalizeDcApiTimeoutMs(dcApiTimeoutMs);
    const timeoutId = window.setTimeout(
      () => controller.abort("DC_API_TIMEOUT"),
      timeoutMs
    );

    try {
      if (!data.requestUri) {
        onError({
          errorCode: "NO_AUTH_REQUEST",
          errorMessage: "VP session response missing requestUri",
        });
        resetState();
        return;
      }
      const signedJwt = await getVpRequestJwt(data.requestUri, controller.signal);
      const credential = await navigator.credentials.get({
        signal: controller.signal,
        digital: {
          requests: [
            {
              protocol: DC_API_PROTOCOL,
              data: { request: signedJwt },
            },
          ],
        },
      });

      if (!credential) {
        onError({
          errorCode: "DC_API_NO_CREDENTIAL",
          errorMessage: "No digital credential was returned",
        });
        resetState();
        return;
      }

      // Slice 1: hold DigitalCredential for Slice 2 submission (no backend ingest yet).
      // onVPProcessed / onVPReceived are intentionally deferred until Slice 2
      // posts to data.submissionUri and calls /vp-session-results.
      sessionStateRef.current = {
        requestId: data.requestId,
        flow: "dc_api",
        submissionUri: data.submissionUri,
        dcApiCredentialData: credential.data,
      };
      isActiveRef.current = false;
      setLoading(false);
    } catch (err) {
      const name = err instanceof DOMException ? err.name : "";
      const abortedForTimeout =
        controller.signal.aborted && controller.signal.reason === "DC_API_TIMEOUT";

      if (abortedForTimeout || name === "TimeoutError") {
        onError({
          errorCode: "DC_API_TIMEOUT",
          errorMessage: "Credential request timed out",
        });
        resetState();
        return;
      }
      if (name === "AbortError" || name === "NotAllowedError") {
        onError({
          errorCode: "DC_API_CANCELLED",
          errorMessage: err instanceof Error ? err.message : "Credential request cancelled",
        });
        resetState();
        return;
      }
      if (isAppError(err)) {
        onError(err);
        resetState();
        return;
      }
      onError({
        errorCode: "DC_API_ERROR",
        errorMessage: err instanceof Error ? err.message : "Digital Credentials API failed",
      });
      resetState();
    } finally {
      window.clearTimeout(timeoutId);
    }
  };

  const startVerification = async () => {
    if (
      isDcApiSupported({
        enableDcApi,
        isSameDeviceFlowEnabled,
        clientId,
      })
    ) {
      await startDcApiVerification();
      return;
    }

    const data = await createVPRequest(false);
    if (!data) return;
    const pdParams = getPresentationDefinitionParams(data);

    if (webWalletBaseUrl) {
      let end = webWalletBaseUrl.length;
      while (end > 0 && webWalletBaseUrl[end - 1] === "/") end--;
      const baseUrl = webWalletBaseUrl.slice(0, end);
      window.location.href = `${baseUrl}/authorize?${pdParams}`;
    } else if (isMobileDevice()) {
      window.location.href = `${protocol || DEFAULT_PROTOCOL}authorize?${pdParams}`;
    } else {
      onError({
        errorMessage: "Same device flow can be enabled in desktop mode for only Web Wallets. Provide a valid webWalletBaseUrl",
        errorCode: "MISSING_WEB_WALLET_BASE_URL"
      });
      resetState();
    }
  };

  useEffect(() => {
    const handleVisibilityChange = () => {
      const { requestId, flow } = sessionStateRef.current;
      if (
        document.visibilityState === "visible" &&
        isActiveRef.current &&
        requestId &&
        flow !== "dc_api"
      ) {
        fetchVPStatus(requestId);
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [fetchVPStatus]);

  useEffect(() => {
    if (!isActiveRef.current) {
      const hash = window.location.hash;
      const params = new URLSearchParams(hash.substring(1));
      const responseCode = params.get("response_code");
      if (responseCode) {
        isActiveRef.current = true;
        fetchVPResult(responseCode);
      } else {
        const { requestId: savedRequestId, flow } = sessionStateRef.current;

        if (savedRequestId && flow !== "dc_api") {
          isActiveRef.current = true;
          setLoading(true);
          fetchVPStatus(savedRequestId);
        }
      }
    }

    return () => {
      isActiveRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!dcqlQuery) {
      throw new Error("dcqlQuery must be provided");
    }
    if (!onVPReceived && !onVPProcessed) {
      throw new Error(
        "Either onVpReceived or onVpProcessed must be provided, but not both"
      );
    }
    if (onVPReceived && onVPProcessed) {
      throw new Error(
        "Both onVPReceived and onVPProcessed cannot be provided simultaneously"
      );
    }
    if (!onQrCodeExpired) {
      throw new Error("onQrCodeExpired callback is required");
    }
    if (!onError) {
      throw new Error("onError callback is required");
    }
  }, [
    createVPRequest,
    onError,
    onQrCodeExpired,
    onVPProcessed,
    onVPReceived,
    dcqlQuery,
    triggerElement,
  ]);

  useEffect(() => {
    if (!triggerElement) {
      if (isSameDeviceFlowEnabled) {
        startVerification();
      } else {
        handleGenerateQRCode();
      }
    }
  }, [triggerElement, isSameDeviceFlowEnabled]);

  return (
    <div className={"ovp-root-div-container"}>
      {loading && <div id="ovp-loader" className={"ovp-loader"} />}

      {!loading && triggerElement && !qrCodeData && (
        <div onClick={handleTriggerClick} style={{ cursor: "pointer" }}>
          {triggerElement}
        </div>
      )}

      {shouldShowQRCode && (
        <QRCodeSVG
          value={qrCodeData}
          size={qrCodeStyles?.size || 200}
          level={qrCodeStyles?.level || "L"}
          bgColor={qrCodeStyles?.bgColor || "#ffffff"}
          fgColor={qrCodeStyles?.fgColor || "#000000"}
          marginSize={qrCodeStyles?.margin || 10}
          style={{ borderRadius: qrCodeStyles?.borderRadius || 10 }}
        />
      )}
    </div>
  );
};

export default OpenID4VPVerification;

