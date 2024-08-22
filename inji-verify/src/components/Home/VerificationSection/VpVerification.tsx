import React from "react";
import QRCode from "react-qr-code";
import { useVerificationFlowSelector } from "../../../redux/features/verification/verificationSelector";

export const VpVerification = () => {
  const qrCodeValue =
    "openid4vp://authorize?request_uri=https://api.jsonserve.com/DNknuO";
  const nonce = useVerificationFlowSelector((state) => state.nonce);

  return (
    <div className="absolute top-[100px] left-[33px] w-[250px] lg:w-[250px] lg:left-[23px] lg:top-[25px]">
      <QRCode size={300} value={qrCodeValue} />
      <div className="mt-5">
        <h5>Nonce: {nonce}</h5>
      </div>
    </div>
  );
};
