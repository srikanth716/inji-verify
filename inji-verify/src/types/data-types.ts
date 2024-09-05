export type QrScanResult = {
  data: string | null;
  error: string | null;
  status: QrReadStatus;
};

export type QrReadStatus = "SUCCESS" | "NOT_READ" | "FAILED";

export type VcStatus = {
  status: "OK" | "NOK" | "Verifying";
  checks: {
    active: string | null;
    revoked: "OK" | "NOK";
    expired: "OK" | "NOK";
    proof: "OK" | "NOK";
  }[];
};

export type VerificationStep = {
  label: string;
  description: string | string[];
};

export type CardPositioning = {
  top?: number;
  right?: number;
  bottom?: number;
  left?: number;
};

export type AlertSeverity =
  | "success"
  | "info"
  | "warning"
  | "error"
  | undefined;

export type AlertInfo = {
  message?: string;
  severity?: AlertSeverity;
  open?: boolean;
  autoHideDuration?: number;
};

export type VerificationMethod =
  | "SCAN"
  | "UPLOAD"
  | "VP_VERIFICATION"
  | "TO_BE_SELECTED";

export type InternetConnectionStatus =
  | "ONLINE"
  | "OFFLINE"
  | "LOADING"
  | "UNKNOWN";

export type ApplicationState = {
  internetConnectionStatus: InternetConnectionStatus;
};

export type VerificationState = {
  method: VerificationMethod;
  activeScreen: number; // Verification steps
  qrReadResult?: QrReadResult | undefined;
  verificationResult?: VerificationResult;
  alert?: AlertInfo;
  ovp?: OvpFlowData;
  selectedCredentialTypes?: string[];
  qrCodeData?: string | null;
};

export type QrReadResult = {
  alert?: AlertInfo;
  qrData?: string;
  status: QrReadStatus;
};

export type OvpFlowData = {
  presentationSubmission?: any;
  vpToken?: any;
};

export type VerificationTrigger = {};

export type VerificationResult = {
  vc?: any;
  vcStatus?: VcStatus;
};

export type HTTP_METHOD = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

type Api_Params = {
  method: HTTP_METHOD; // Define the HTTP methods
  buildURL: (param?: string) => `/${string}`; // Define the buildURL function signature
};

export type ApiUrls = {
  getQrCode: Api_Params;
};
