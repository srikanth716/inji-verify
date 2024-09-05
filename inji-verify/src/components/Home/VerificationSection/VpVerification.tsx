import React from "react";
import Button from "../../commons/Button";
import { ReactComponent as RightArrow } from "../../../assets/arrow-right.svg";
import { useVerificationFlowSelector } from "../../../redux/features/verification/verificationSelector";
import { useAppDispatch } from "../../../redux/hooks";
import { generateQrCode } from "../../../redux/features/verification/verificationSlice";
import { raiseAlert } from "../../../redux/features/alerts/alertsSlice";
import { AlertMessages } from "../../../utils/config";

export const VpVerification = () => {
  const dispatch = useAppDispatch();
  const selectedVcType = useVerificationFlowSelector(
    (state) => state.selectedCredentialTypes
  );
  const activeScreen = useVerificationFlowSelector(
    (state) => state.activeScreen
  );
  console.log(activeScreen);

  const handleGenerateQrCode = () => {
    if (selectedVcType.length > 0) {
      dispatch(generateQrCode({ selectedTypes: selectedVcType }));
    } else {
      dispatch(
        raiseAlert({
          ...AlertMessages.vcTypeNotSelected,
          open: true,
        })
      );
    }
  };

  return (
    <div className="absolute top-[100px] left-[33px] w-[250px] lg:w-[250px] lg:left-[50px] lg:top-[150px] flex items-center justify-center">
      <Button
        id="scan-button"
        title="Generate QR"
        className="text-center inline-flex w-[205px] lg:w-[223px] fill-primary hover:fill-white"
        fill={false}
        iconRight={<RightArrow className="fill-inherit" />}
        onClick={handleGenerateQrCode}
      />
    </div>
  );
};
