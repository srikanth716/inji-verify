import { all, call, delay, put, takeLatest } from "redux-saga/effects";
import { api } from "../../../utils/api";
import { ApiRequest, QrData, RequestStatus } from "../../../types/data-types";
import {
  getVpRequest,
  resetVpRequest,
  setVpRequestResponse,
  setVpRequestStatus,
  verificationSubmissionComplete,
} from "./verifyState";
import {
  AlertMessages,
  OPENID4VP_PROTOCOL,
  PollStatusDelay,
} from "../../../utils/config";
import { raiseAlert } from "../alerts/alerts.slice";

function* fetchRequestUri(claims: string[]) {
  let qrData;
  let txnId;
  let reqId;
  const apiRequest: ApiRequest = api.fetchVpRequest;
  const requestOptions = {
    method: apiRequest.methodType,
    headers: apiRequest.headers(),
    body: apiRequest.body,
  };

  try {
    const response: Response = yield call(
      fetch,
      apiRequest.url(),
      requestOptions
    );
    const data: string = yield response.text();
    const parsedData = JSON.parse(data) as QrData;
    qrData =
      OPENID4VP_PROTOCOL +
      btoa(
        `client_id=${parsedData.authorizationDetails.clientId}` +
          `&response_type=${parsedData.authorizationDetails.responseType}` +
          `&response_mode=direct_post` +
          `&nonce=${parsedData.authorizationDetails.nonce}` +
          `&state=${parsedData.requestId}` +
          `&response_uri=${
            window.location.origin +
            window._env_.VERIFY_SERVICE_API_URL +
            parsedData.authorizationDetails.responseUri
          }` +
          `&presentation_definition_uri=${
            window.location.origin +
            window._env_.VERIFY_SERVICE_API_URL +
            parsedData.authorizationDetails.presentationDefinitionUri
          }` +
          `&client_metadata={"client_name":"${window.location.origin}"}`
      );
    txnId = parsedData.transactionId;
    reqId = parsedData.requestId;
  } catch (error) {
    console.error("Failed to fetch request URI:", error);
    yield put(resetVpRequest());
    yield put(raiseAlert({ ...AlertMessages().failToGenerateQrCode, open: true }));
    return;
  }

  yield put(setVpRequestResponse({ qrData: qrData, txnId: txnId, reqId: reqId }));
  return;
}

function* getVpStatus(reqId: string, txnId: string) {
  const apiRequest: ApiRequest = api.fetchStatus;
  const requestOptions = {
    method: apiRequest.methodType,
    headers: apiRequest.headers(),
  };

  const pollStatus: any = function* () {
    try {
      const response: Response = yield call(
        fetch,
        apiRequest.url(reqId),
        requestOptions
      );
      const data: string = yield response.text();
      const parsedData = JSON.parse(data);
      const status:RequestStatus = parsedData.status;
      if (status !== "ACTIVE") {
        yield put(setVpRequestStatus({ status, txnId, qrData: "" }));
        return;
      } else {
        yield delay(PollStatusDelay);
        yield call(pollStatus);
      }
    } catch (error) {
      console.error("Error occurred:", error);
      yield put(resetVpRequest());
      yield put(raiseAlert({ ...AlertMessages().unexpectedError, open: true }));
      return;
    }
  };

  yield call(pollStatus);
}

function* getVpResult(status: string, txnId: string) {
  if (status === "VP_SUBMITTED") {
    const apiRequest: ApiRequest = api.fetchVpResult;
    const requestOptions = {
      method: apiRequest.methodType,
      headers: apiRequest.headers(),
    };
    try {
      const response: Response = yield call(
        fetch,
        apiRequest.url(txnId),
        requestOptions
      );
      const data: string = yield response.text();
      const parsedData = JSON.parse(data);
      const verifiablePresentations = parsedData.vcresults[0]
      const verificationStatus = parsedData.vcresults[0].verificationStatus;
      const vc1 = JSON.parse(verifiablePresentations.vc);
      yield put(
        verificationSubmissionComplete({
          verificationResult: {
            vc: vc1,
            vcStatus: verificationStatus,
          },
        })
      );
      return;
    } catch (error) {
      console.error("Error occurred:", error);
      yield put(resetVpRequest());
      yield put(raiseAlert({ ...AlertMessages().unexpectedError, open: true }));
      return;
    }
  }
}

function* verifySaga() {
  yield all([
    takeLatest(getVpRequest, function* ({ payload }) {
      yield call(fetchRequestUri, payload.selectedClaims);
    }),
    takeLatest(setVpRequestResponse, function* ({ payload }) {
      yield call(getVpStatus, payload.reqId, payload.txnId);
    }),
    takeLatest(setVpRequestStatus, function* ({ payload }) {
      yield call(getVpResult, payload.status, payload.txnId);
    }),
  ]);
}

export default verifySaga;
