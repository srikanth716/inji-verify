import React from "react";
import scanQr from "../../../assets/scanner-ouline.svg";
import qrIcon from "../../../assets/qr-code-icon.svg";
import { ReactComponent as TabScanFillIcon } from "../../../assets/tab-scan-fill.svg";
import Button from "../../commons/Button";
import { UploadQrCode } from "./UploadQrCode";
import { useAppDispatch } from "../../../redux/hooks";
import { qrReadInit } from "../../../redux/features/verification/verificationSlice";
import { useVerificationFlowSelector } from "../../../redux/features/verification/verificationSelector";
import { checkInternetStatus } from "../../../utils/misc";
import { updateInternetConnectionStatus } from "../../../redux/features/application-state/applicationSlice";
import { VpVerification } from "./VpVerification";
import { VerifiableCredentialTypes } from "../../../utils/config";

const Scan = () => {
  const dispatch = useAppDispatch();
  return (
    <>
      <Button
        id="scan-button"
        title="Scan"
        fill={false}
        iconLeft={<TabScanFillIcon className="fill-inherit" />}
        className="mx-0 my-1.5 py-3 text-center inline-flex absolute top-[160px] left-[33px] w-[205px] lg:w-[223px] lg:left-[63px] lg:top-[231px] fill-[#ff7f00] hover:fill-white"
        onClick={async () => {
          dispatch(
            updateInternetConnectionStatus({
              internetConnectionStatus: "LOADING",
            })
          );
          let isOnline = await checkInternetStatus();
          dispatch(
            updateInternetConnectionStatus({
              internetConnectionStatus: isOnline ? "ONLINE" : "OFFLINE",
            })
          );
          if (isOnline) {
            dispatch(qrReadInit({ method: "SCAN" }));
          }
        }}
      />
    </>
  );
};

const Upload = () => (
  <>
    <UploadQrCode
      className="absolute top-[160px] left-[33px] w-[205px] lg:w-[223px] lg:left-[63px] lg:top-[231px]"
      displayMessage="Upload"
    />
  </>
);
const display = (tab: String) => {
  switch (tab) {
    case "SCAN":
      return <Scan />;
    case "VP_VERIFICATION":
      return <VpVerification />;
    default:
      return <Upload />;
  }
};
const ScanQrCode = () => {
  const method = useVerificationFlowSelector((state) => state.method);
  console.log({ method });
  return (
    <div className="flex flex-col pt-0 pb-[100px] lg:py-[42px] px-0 lg:px-[104px] text-center content-center justify-center">
      <div className="xs:col-end-13">
        {method === "VP_VERIFICATION" && (
          <div className="grid text-center content-center justify-center">
            <select
              id="CredentialTypeSelector"
              defaultValue="Select Credential Type"
              className="w-[300px] border border-gray-300 rounded-md p-2"
              onChange={(e) => console.log(e.target.value)}
            >
              <option value="Select Credential Type" disabled>
                Select Credential Type
              </option>
              {VerifiableCredentialTypes.map((type) => (
                <option value={type}>{type}</option>
              ))}
            </select>
          </div>
        )}
        <div
          className={`relative grid content-center justify-center w-[275px] lg:w-[350px] aspect-square my-1.5 mx-auto bg-cover`}
          style={{ backgroundImage: `url(${scanQr})` }}
        >
          <div className="grid bg-primary opacity-5 rounded-[12px] w-[250px] lg:w-[320px] aspect-square content-center justify-center"></div>
          <div className="absolute top-[58px] left-[98px] lg:top-[165px] lg:left-[50%] lg:translate-x-[-50%] lg:translate-y-[-50%]">
            <img src={qrIcon} className="w-[78px] lg:w-[100px]" alt="qr-icon" />
          </div>
          {display(method)}
        </div>
        {method === "UPLOAD" && (
          <div className="grid text-center content-center justify-center pt-2">
            <p
              id="file-format-constraints"
              className="font-normal text-[14px] text-[#8E8E8E] w-[280px]"
            >
              Allowed file formats: PNG/JPEG/JPG/PDF <br />
              Min Size : 10KB | Max Size : 5MB
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanQrCode;
