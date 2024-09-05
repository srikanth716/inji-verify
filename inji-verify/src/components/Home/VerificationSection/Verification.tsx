import React from "react";
import scanQr from "../../../assets/scanner-ouline.svg";
import Loader from "../../commons/Loader";
import QrScanner from "./QrScanner";
import { useAppDispatch } from "../../../redux/hooks";
import { goHomeScreen } from "../../../redux/features/verification/verificationSlice";
import { VerificationSteps } from "../../../utils/config";
import { useVerificationFlowSelector } from "../../../redux/features/verification/verificationSelector";
import { terminateScanning } from "../../../utils/qr-utils";
import Button from "../../commons/Button";
import QRCode from "react-qr-code";

const Qrcode = () => {
  const qrCodeData = useVerificationFlowSelector((state) => state.qrCodeData);
  return (
    <div className="relative h-[250px] w-[250px] lg:h-[316px] lg:w-[316px] rounded-lg flex items-center justify-center">
      <QRCode size={300} value={qrCodeData} />
    </div>
  );
};

const Verification = () => {
  const dispatch = useAppDispatch();
  const { activeScreen, method } = useVerificationFlowSelector((state) => ({
    activeScreen: state.activeScreen,
    method: state.method,
  }));
  console.log({ activeScreen });
  return (
    <div className="grid grid-cols-12 mx-auto pt-1 pb-[100px] px-[16px] lg:py-[42px] lg:px-[104px] text-center content-center justify-center">
      <div
        className="col-start-1 col-end-13 grid w-[100%] lg:w-[350px] aspect-square max-w-[280px] lg:max-w-none bg-cover content-center justify-center m-auto"
        style={{
          backgroundImage: `url(${scanQr})`,
        }}
      >
        {activeScreen === VerificationSteps[method].Verifying ? (
          <Loader />
        ) : method === "VP_VERIFICATION" ? (
          <Qrcode />
        ) : (
          <QrScanner />
        )}
      </div>
      <div className="col-span-12">
        <Button
          id="verification-back-button"
          title="Back"
          className="w-[100%] lg:w-[350px] max-w-[280px] lg:max-w-none mt-[18px]"
          onClick={() => {
            terminateScanning();
            dispatch(goHomeScreen({}));
          }}
        />
      </div>
    </div>
  );
};

export default Verification;
