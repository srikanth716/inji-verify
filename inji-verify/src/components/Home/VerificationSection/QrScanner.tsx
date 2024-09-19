import React, { useEffect, useRef, useState } from "react";
import CameraAccessDenied from "./CameraAccessDenied";
import { AlertMessages, ScanSessionExpiryTime } from "../../../utils/config";
import { useAppDispatch } from "../../../redux/hooks";
import {
  goHomeScreen,
  verificationInit,
} from "../../../redux/features/verification/verification.slice";
import { raiseAlert } from "../../../redux/features/alerts/alerts.slice";
import "./ScanningLine.css";
import {
  BarcodeFormat,
  BrowserQRCodeReader,
  FormatException,
} from "@zxing/library";

let timer: NodeJS.Timeout;

function QrScanner() {
  const dispatch = useAppDispatch();
  const [isCameraBlocked, setIsCameraBlocked] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [useHighResolution, setUseHighResolution] = useState<boolean>(false); // State for high resolution toggle
  const codeReader = useRef<BrowserQRCodeReader | null>(null);
  const scannerRef = useRef<HTMLDivElement>(null);
  const [zoomLevel, setZoomLevel] = useState(1); // New state for zoom level

  const getHighestAvailableResolutionConstraints = () => {
    return {
      video: {
        facingMode: { exact: "environment" },
        height: { ideal: 2160 },
        width: { ideal: 3840 },
        frameRate: { ideal: 30 },
        aspectRatio: { ideal: 9 / 16 },
        autoFocus: true,
      },
      barcode: {
        formats: [BarcodeFormat.QR_CODE, BarcodeFormat.DATA_MATRIX],
      },
    };
  };

  const getDefaultResolutionConstraints = () => {
    return {
      video: {
        facingMode: "environment",
      },
      barcode: {
        formats: [BarcodeFormat.QR_CODE, BarcodeFormat.DATA_MATRIX],
      },
    };
  };

  const toggleHighResolution = () => {
    if (!useHighResolution) {
      setUseHighResolution(true);
      setZoomLevel(2.4);
    } else {
      setUseHighResolution(false);
      setZoomLevel(1);
    }
  };
  // Start the scanner
  const startScanner = async () => {
    try {
      const devices = await codeReader.current?.getVideoInputDevices();
      if (devices?.length === 0) {
        console.error("No camera devices found.");
        setIsCameraBlocked(true);
        return;
      }

      // Get the appropriate constraints based on the toggle state
      const constraints = useHighResolution
        ? await getHighestAvailableResolutionConstraints()
        : getDefaultResolutionConstraints();

      await codeReader.current?.decodeFromConstraints(
        constraints,
        videoRef.current!,
        (result, err) => {
          if (result) {
            dispatch(
              verificationInit({
                qrReadResult: {
                  qrData: result.getText(),
                  status: "SUCCESS",
                },
                flow: "SCAN",
              })
            );
            clearTimeout(timer);
            stopScanner();
          }
          if (err && err instanceof FormatException) {
            console.error("Error occurred:", err);
            dispatch(
              raiseAlert({ ...AlertMessages.qrNotSupported, open: true })
            );
            dispatch(goHomeScreen({}));
            stopScanner();
          }
        }
      );
    } catch (e) {
      console.error("Failed to start the scanner: " + e);
      setIsCameraBlocked(true);
    }
  };

  // Stop the scanner
  const stopScanner = () => {
    if (codeReader.current) {
      codeReader.current.reset();
    }
  };

  useEffect(() => {
    codeReader.current = new BrowserQRCodeReader();
    startScanner();
    return () => {
      stopScanner();
    };
  }, [useHighResolution]);

  useEffect(() => {
    timer = setTimeout(() => {
      dispatch(goHomeScreen({}));
      dispatch(
        raiseAlert({
          open: true,
          message:
            "The scan session has expired due to inactivity. Please initiate a new scan.",
          severity: "error",
        })
      );
      stopScanner();
    }, ScanSessionExpiryTime);
    return () => {
      console.log("Clearing timeout");
      clearTimeout(timer);
    };
  }, [dispatch]);

  useEffect(() => {
    // Disable inbuilt border around the video
    if (scannerRef?.current) {
      let svgElements = scannerRef?.current?.getElementsByTagName("svg");
      if (svgElements.length === 1) {
        svgElements[0].style.display = "none";
      }
    }
  }, [scannerRef]);

  return (
    <div
      ref={scannerRef}
      className="fixed inset-0 flex items-center justify-center overflow-hidden lg:relative lg:overflow-visible"
    >
      {!isCameraBlocked && (
        <div className="absolute top-[-15px] left-[-15px] h-[280px] w-[280px] lg:top-[-12px] lg:left-[-12px] lg:h-[340px] lg:w-[340px] flex items-center justify-center">
          <div
            id="scanning-line"
            className="hidden lg:block scanning-line"
          ></div>
        </div>
      )}

      <div className="relative h-screen w-screen lg:h-[316px] lg:w-[316px] rounded-lg overflow-hidden flex items-center justify-center z-0">
        <button
          onClick={() => {
            stopScanner();
            dispatch(goHomeScreen({}));
          }}
          className="absolute top-10 right-4 lg:hidden bg-gray-800 text-white p-2 rounded-full hover:bg-gray-700 focus:outline-none z-20"
          aria-label="Close Scanner"
        >
          ✕
        </button>

        <video
          ref={videoRef}
          className="h-full w-full object-cover rounded-lg"
          autoPlay
          playsInline
          style={{
            transform: `scale(${zoomLevel})`,
            transformOrigin: "center",
          }}
        />

        <div className="absolute bottom-14 left-4 lg:hidden flex flex-row">
          <p className="text-primary font-bold mr-1"> High Resolution</p>
          <label className="inline-block relative bottom-0 w-10 h-5">
            <input
              type="checkbox"
              className="peer hidden"
              id="toggle"
              checked={useHighResolution}
              onChange={toggleHighResolution}
            />
            <span className="peer-checked:bg-primary peer-focus:ring peer-focus:ring-primary absolute cursor-pointer top-0 left-0 right-0 bottom-0 bg-gray-400 rounded-full transition" />
            <span className="absolute left-1 h-5 w-5 rounded-full bg-white transition transform-translate-x-1 peer-checked:translate-x-5" />
          </label>
        </div>
      </div>

      <CameraAccessDenied
        open={isCameraBlocked}
        handleClose={() => {
          console.log("closing camera");
          dispatch(goHomeScreen({}));
          setIsCameraBlocked(false);
        }}
      />
    </div>
  );
}

export default QrScanner;
