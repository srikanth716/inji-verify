beforeEach(() => {
    global.fetch = jest.fn();
});
beforeEach(() => {
    jest.clearAllMocks();
});

import React from "react";
import "@testing-library/jest-dom";
import {
  render,
  screen,
  waitFor,
  fireEvent,
  act,
} from "@testing-library/react";
import OpenID4VPVerification from "../../../src/components/openid4vp-verification/OpenID4VPVerification";

jest.mock("qrcode.react", () => ({
  QRCodeSVG: ({ value }: { value: string }) => (
    <div data-testid="ovp-qr" data-qr={value} />
  ),
}));

const mockFetchError = (message = "Failed to fetch") => {
  global.fetch = jest.fn(() => Promise.reject(new Error(message))) as jest.Mock;
};

describe("OpenID4VPVerification UI Tests", () => {
  const verifyServiceUrl = "https://example.com/verify";
  const protocol = "testopenid4vp://";
  const dcqlQuery = {
    credentials: [{ id: "id-1", format: "dc+sd-jwt", meta: {}, claims: [] }],
  };
  const onVPReceived = jest.fn();
  const onVPProcessed = jest.fn();
  const onQrCodeExpired = jest.fn();
  const onError = jest.fn();
  const qrCodeStyles = {
    size: 150,
    level: "H",
    bgColor: "#f0f0f0",
    fgColor: "#333",
    margin: 5,
    borderRadius: 5,
  };
  const triggerElement = <button>Verify</button>;

  const authorizationDetails = () => {
    return {
      responseType: "vp_token",
      responseMode: "direct_post",
      clientId: "test-client",
      dcqlQuery,
      responseUri: "https://example.com/response",
      nonce: "nonce",
      iat: 1,
    };
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Mock window.location for each test (jsdom may not have hash/search)
    Object.defineProperty(window, "location", {
      value: {
        origin: "https://client.example.com",
        search: "",
        hash: "",
        href: "https://client.example.com/",
        pathname: "/",
      },
      writable: true,
    });
  });

  // Helper function to render the component with common props
  const renderComponent = (
    props: Partial<React.ComponentProps<typeof OpenID4VPVerification>> = {}
  ) => {
    const {
      onVPReceived: received,
      onVPProcessed: processed,
      onQrCodeExpired: qrExpired = onQrCodeExpired,
      onError: errorCb = onError,
      clientId = "test-client",
      dcqlQuery: dq = dcqlQuery,
      ...rest
    } = props;

    const vpCallback =
      processed != null
        ? { onVPProcessed: processed }
        : { onVPReceived: received ?? onVPReceived };

    return render(
      <OpenID4VPVerification
        verifyServiceUrl={verifyServiceUrl}
        protocol={protocol}
        clientId={clientId}
        dcqlQuery={dq}
        onQrCodeExpired={qrExpired}
        onError={errorCb}
        {...rest}
        {...vpCallback}
      />
    );
  };

  it("should render the trigger element", () => {
    renderComponent({
      onVPReceived,
      onQrCodeExpired,
      onError,
      triggerElement,
    });
    expect(screen.getByRole("button", { name: "Verify" })).toBeInTheDocument();
  });

  it("should indicate QR code expiry after a timeout (mocking status)", async () => {
    const fetchMock = jest
      .fn()
      // First call: createRequest
      .mockResolvedValueOnce({
        status: 201,
        json: async () => ({
          transactionId: "mock-txn-id",
          requestId: "mock-req-id",
          authorizationDetails: authorizationDetails(),
        }),
      })
      // Second call: status polling
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({ status: "EXPIRED" }),
      });

    global.fetch = fetchMock;

    renderComponent({
      onVPReceived,
      onQrCodeExpired,
      onError,
      triggerElement,
      isSameDeviceFlowEnabled: false,
    });

    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(onQrCodeExpired).toHaveBeenCalled(), {
      timeout: 10000,
    });
  }, 15000);

  it("should handle API error during request creation", async () => {
    const consoleErrorMock = jest
      .spyOn(console, "error")
      .mockImplementation(() => {});
    mockFetchError("Failed to create request");

    renderComponent({
      onVPReceived,
      onQrCodeExpired,
      onError,
      triggerElement, // ✅ Add this!
    });

    // Wait for the button to render
    await waitFor(() => screen.getByRole("button", { name: "Verify" }));

    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith(
        new Error("Failed to create request")
      )
    );

    expect(screen.queryByRole("img")).toBeNull();
    consoleErrorMock.mockRestore();
  });

  it("should display the QR code after successful request", async () => {
    const mockTransactionId = "mock-txn-id";
    const mockRequestId = "mock-req-id";

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        status: 201,
        json: async () => ({
          transactionId: mockTransactionId,
          requestId: mockRequestId,
          authorizationDetails: authorizationDetails(),
        }),
      })
      .mockResolvedValue({
        status: 200,
        json: async () => ({ status: "PENDING" }),
      });

    global.fetch = fetchMock;

    renderComponent({
      clientId: "test-client",
      isSameDeviceFlowEnabled: false,
      onVPReceived,
      onQrCodeExpired,
      onError,
      triggerElement,
    });

    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => {
      expect(screen.getByTestId("ovp-qr")).toBeInTheDocument();
    });
  });

  it("should handle onVPReceived after VP_SUBMITTED status", async () => {
    const mockTransactionId = "mock-txn-id";
    const mockRequestId = "mock-req-id";

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        status: 201,
        json: async () => ({
          transactionId: mockTransactionId,
          requestId: mockRequestId,
          authorizationDetails: authorizationDetails(),
        }),
      })
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({ status: "VP_SUBMITTED" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ credentialResults: [], transactionId: mockTransactionId }),
      });

    global.fetch = fetchMock;

    const onVPReceived = jest.fn();
    const onQrCodeExpired = jest.fn();
    const onError = jest.fn();

    renderComponent({
      onVPReceived,
      onQrCodeExpired,
      onError,
      triggerElement: <button>Verify</button>,
      isSameDeviceFlowEnabled: false,
    });

    // Trigger the creation of the VP request
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    // Wait for the VP result to be received
    await waitFor(() => {
      expect(onVPReceived).toHaveBeenCalledWith(mockTransactionId); // Expect txnId
    });
  });

    it("should throw error if both onVPReceived and onVPProcessed are provided", async () => {
        const errorMessage =
            "Both onVPReceived and onVPProcessed cannot be provided simultaneously";
        const consoleErrorMock = jest
            .spyOn(console, "error")
            .mockImplementation(() => {});

        class ErrorBoundary extends React.Component<
            { children: React.ReactNode },
            { error: Error | null }
        > {
            constructor(props: any) {
                super(props);
                this.state = { error: null };
            }

            static getDerivedStateFromError(error: Error) {
                return { error };
            }

            render() {
                if (this.state.error) {
                    return (
                        <div data-testid="error-message">{this.state.error.message}</div>
                    );
                }
                return this.props.children;
            }
        }

        render(
            <ErrorBoundary>
                <OpenID4VPVerification
                    verifyServiceUrl="https://example.com/verify"
                    clientId="test-client"
                    protocol="testopenid4vp://"
                    dcqlQuery={dcqlQuery}
                    onVPReceived={jest.fn()}
                    onVPProcessed={jest.fn()}
                    onQrCodeExpired={jest.fn()}
                    onError={jest.fn()}
                    triggerElement={<button>Verify</button>}
                />
            </ErrorBoundary>
        );

        await waitFor(() => {
            expect(screen.getByTestId("error-message")).toHaveTextContent(
                errorMessage
            );
        });

        consoleErrorMock.mockRestore();
    });

    it("should handle VP result with dcqlQuery and summariseResults=true", async () => {
        const mockTransactionId = "mock-txn-id";
        const mockRequestId = "mock-req-id";

        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce({
                ok: true,
                status: 201,
                json: async () => ({
                    transactionId: mockTransactionId,
                    requestId: mockRequestId,
                    authorizationDetails: authorizationDetails(),
                }),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({ status: "VP_SUBMITTED" }),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({
                    credentialResults: [
                        {
                            verifiableCredential: JSON.stringify({ id: "vc1" }),
                            allChecksSuccessful: true,
                        },
                        {
                            verifiableCredential: JSON.stringify({ id: "vc2" }),
                            allChecksSuccessful: false,
                            expiryCheck: { valid: false },
                        },
                    ],
                }),
            });

        global.fetch = fetchMock as jest.Mock;

        const onVPProcessed = jest.fn();

        render(
            <OpenID4VPVerification
                verifyServiceUrl="https://example.com/verify"
                clientId="test-client"
                protocol="testopenid4vp://"
                dcqlQuery={{ credentials: [{ id: "email_input", format: "dc+sd-jwt", meta: {}, claims: [] }] }}
                isSameDeviceFlowEnabled={false}
                onVPProcessed={onVPProcessed}
                onQrCodeExpired={jest.fn()}
                onError={jest.fn()}
                triggerElement={<button>Verify</button>}
                vpVerificationRequest={{}}
                summariseResults={true}
            />
        );

        fireEvent.click(screen.getByRole("button", { name: "Verify" }));

        await waitFor(() => {
            expect(onVPProcessed).toHaveBeenCalledTimes(1);
        });

        const result = onVPProcessed.mock.calls[0][0];

        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBeGreaterThan(0);

        const response = result[0].verificationResponse;

        expect(response).toMatchObject({
            vpResultStatus: "INVALID",
        });

        expect(response.vcResults).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    vc: { id: "vc1" },
                    vcStatus: "SUCCESS",
                }),
                expect.objectContaining({
                    vc: { id: "vc2" },
                    vcStatus: "EXPIRED",
                }),
            ])
        );
    });

  it("should generate QR code using dcql_query", async () => {
    const mockTransactionId = "txn789";
    const mockRequestId = "req789";
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce({
        status: 201,
        json: async () => ({
          transactionId: mockTransactionId,
          requestId: mockRequestId,
          authorizationDetails: authorizationDetails(),
        }),
      })
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({ status: "PENDING" }),
      }) as jest.Mock;
  
    render(
      <OpenID4VPVerification
        verifyServiceUrl="https://example.com"
        clientId="test-client"
        protocol="testopenid4vp://"
        dcqlQuery={dcqlQuery}
        isSameDeviceFlowEnabled={false}
        onVPProcessed={onVPProcessed}
        onQrCodeExpired={jest.fn()}
        onError={jest.fn()}
        triggerElement={<button>Verify</button>}
      />
    );
  
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
  
    await waitFor(() => {
      const qrHost = screen.getByTestId("ovp-qr");
      expect(qrHost).toBeInTheDocument();
      const qrValue = qrHost.getAttribute("data-qr");
      expect(qrValue).toBeTruthy();
      expect(qrValue as string).toContain("dcql_query=");
    });
  });

  describe("cross-device DC API", () => {
    const didClientId = "decentralized_identifier:did:web:example.com";
    const originalUserAgent = navigator.userAgent;
    const originalDigitalCredential = window.DigitalCredential;
    const originalCredentials = navigator.credentials;

    const mockMobileDcApi = () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      });
      window.DigitalCredential = {
        userAgentAllowsProtocol: jest.fn(() => true),
      } as unknown as typeof DigitalCredential;
      const get = jest.fn().mockResolvedValue({
        protocol: "openid4vp-v1-signed",
        data: { vp_token: { cred: "token" } },
      });
      Object.defineProperty(navigator, "credentials", {
        configurable: true,
        value: { get },
      });
      return get;
    };

    afterEach(() => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: originalUserAgent,
      });
      Object.defineProperty(navigator, "credentials", {
        configurable: true,
        value: originalCredentials,
      });
      if (originalDigitalCredential === undefined) {
        delete (window as { DigitalCredential?: unknown }).DigitalCredential;
      } else {
        window.DigitalCredential = originalDigitalCredential;
      }
    });

    it("uses DC API instead of QR when enableDcApi, mobile, and DC API are supported", async () => {
      const credentialsGet = mockMobileDcApi();
      const fetchMock = jest
        .fn()
        .mockResolvedValueOnce({
          status: 201,
          json: async () => ({
            transactionId: "txn-dc",
            requestId: "req-dc",
            requestUri: "https://example.com/verify/v2/vp-request/req-dc",
            responseUri: "https://example.com/verify/vp-submission/dc-api",
            authorizationDetails: {
              ...authorizationDetails(),
              responseMode: "dc_api",
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: async () => "signed.jwt.here",
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({}),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            credentialResults: [],
            transactionId: "txn-dc",
          }),
        });
      global.fetch = fetchMock;

      renderComponent({
        clientId: didClientId,
        enableDcApi: true,
        isSameDeviceFlowEnabled: false,
        triggerElement,
        onVPReceived,
      });

      fireEvent.click(screen.getByRole("button", { name: "Verify" }));

      await waitFor(() => {
        expect(credentialsGet).toHaveBeenCalled();
      });
      expect(screen.queryByTestId("ovp-qr")).not.toBeInTheDocument();

      const sessionBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(sessionBody.responseMode).toBe("dc_api");
      expect(onVPReceived).toHaveBeenCalledWith("txn-dc");
    });

    it("still shows QR on cross-device when enableDcApi is false", async () => {
      mockMobileDcApi();
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({
          status: 201,
          json: async () => ({
            transactionId: "txn-qr",
            requestId: "req-qr",
            authorizationDetails: authorizationDetails(),
          }),
        })
        .mockResolvedValue({
          status: 200,
          json: async () => ({ status: "PENDING" }),
        }) as jest.Mock;

      renderComponent({
        clientId: didClientId,
        enableDcApi: false,
        isSameDeviceFlowEnabled: false,
        triggerElement,
      });

      fireEvent.click(screen.getByRole("button", { name: "Verify" }));

      await waitFor(() => {
        expect(screen.getByTestId("ovp-qr")).toBeInTheDocument();
      });
      expect(navigator.credentials.get).not.toHaveBeenCalled();
    });
  });
});
