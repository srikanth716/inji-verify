import React, { useState } from "react";
import QRCode from "react-qr-code";
import { useVerificationFlowSelector } from "../../../redux/features/verification/verificationSelector";
import Button from "./commons/Button";

export const VpVerification = () => {
  // const nonce = useVerificationFlowSelector((state) => state.nonce);
  const [qrCodeValue, setqrCodeValue] = useState("");
  return (
    <div>
      {qrCodeValue ? (
        <div className="absolute top-[100px] left-[33px] w-[250px] lg:w-[250px] lg:left-[23px] lg:top-[25px]">
          <QRCode size={300} value={qrCodeValue} />
        </div>
      ) : (
        <div className="absolute top-[100px] left-[33px] w-[250px] lg:w-[250px] lg:left-[50px] lg:top-[150px] flex items-center justify-center">
          <Button
            id="scan-button"
            title="Generate QR Code"
            className="text-center inline-flex w-[205px] lg:w-[223px] fill-[#24a0ed] hover:fill-white"
            fill={false}
            onClick={async (event) => {
              setqrCodeValue(
                "openid4vp://authorize?request_uri=https://api.jsonserve.com/DNknuO"
              );
            }}
          />
        </div>
      )}
    </div>
  );
};
