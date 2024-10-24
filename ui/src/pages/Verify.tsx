import React from "react";
import PageTemplate from "../components/PageTemplate";
import VerificationProgressTracker from "../components/Home/VerificationProgressTracker";
import { VpVerification } from "../components/Home/VerificationSection/VpVerification";

export function Verify() {
  return (
    <PageTemplate>
      <div className="grid grid-cols-12">
        <div className="col-start-1 col-end-13 lg:col-start-1 lg:col-span-6 lg:bg-pageBackGroundColor xs:w-[100vw] lg:max-w-[50vw]">
          <VerificationProgressTracker />
        </div>
        <div className="col-start-1 col-end-13 lg:col-start-7 lg:col-end-13 xs:[100vw] lg:max-w-[50vw]">
          <VpVerification />
        </div>
      </div>
    </PageTemplate>
  );
}