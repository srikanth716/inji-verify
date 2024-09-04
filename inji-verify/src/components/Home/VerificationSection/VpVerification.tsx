import React, { useState } from "react";
import QRCode from "react-qr-code";
import Button from "../../commons/Button";
import { ReactComponent as RightArrow } from "../../../assets/arrow-right.svg";

export const VpVerification = () => {
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
            title="Generate QR"
            className="text-center inline-flex w-[205px] lg:w-[223px] fill-primary hover:fill-white"
            fill={false}
            iconRight={<RightArrow className="fill-inherit" />}
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
