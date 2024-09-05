import { createSlice } from "@reduxjs/toolkit";
import { VerificationState } from "../../../types/data-types";
import { VerificationSteps } from "../../../utils/config";

export const PreloadedState: VerificationState = {
  method: "UPLOAD",
  activeScreen: VerificationSteps["UPLOAD"].QrCodePrompt,
  alert: {},
  qrReadResult: { status: "NOT_READ" },
  verificationResult: { vc: undefined, vcStatus: undefined },
  ovp: {},
  selectedCredentialTypes: [],
  qrCodeData: null,
};

const verificationSlice = createSlice({
  name: "VcVerification",
  initialState: PreloadedState,
  reducers: {
    selectMethod: (state, action) => {
      state.method = action.payload.method;
    },
    qrReadInit: (state, action) => {
      const method = action.payload.method;
      state.activeScreen =
        method === "SCAN"
          ? VerificationSteps[state.method].ActivateCamera
          : VerificationSteps[method].Verifying;
      state.method = method;
    },
    // qrReadComplete and init verification
    verificationInit: (state, action) => {
      state.activeScreen = VerificationSteps[state.method].Verifying;
      state.qrReadResult = action.payload.qrReadResult;
      state.ovp = action.payload;
    },
    verificationComplete: (state, action) => {
      state.activeScreen = VerificationSteps[state.method].DisplayResult;
      state.verificationResult = action.payload.verificationResult;
    },
    goHomeScreen: (state, action) => {
      state.qrReadResult = { status: "NOT_READ" };
      state.activeScreen = VerificationSteps[state.method].QrCodePrompt;
      state.verificationResult = { vc: undefined, vcStatus: undefined };
      state.method = action.payload.method ?? state.method;
      state.ovp = {};
    },
    setSelectedVcTypes: (state, action) => {
      console.log(action.payload.selectedCredentialTypes);
      state.selectedCredentialTypes = action.payload.selectedCredentialTypes;
    },
    generateQrCode: (state, action) => {},
    SetAuthorizationResponse: (state, action) => {
      const method = action.payload.method;
      state.qrCodeData = action.payload.AuthorizationResponse;
      state.method = method;
      state.activeScreen = VerificationSteps[method].DisplayQrCode;
      state.selectedCredentialTypes = [];
    },
  },
});

export const {
  qrReadInit,
  verificationInit,
  verificationComplete,
  goHomeScreen,
  selectMethod,
  setSelectedVcTypes,
  generateQrCode,
  SetAuthorizationResponse,
} = verificationSlice.actions;

export default verificationSlice.reducer;
