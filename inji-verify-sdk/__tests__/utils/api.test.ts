import { vpRequest, vpSessionRequest } from "../../src/utils/api";

describe("vp request api errors", () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  it("vpRequest surfaces verify-service 400 error body", async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      status: 400,
      json: async () => ({
        errorCode: "dcql_query.credentials",
        errorMessage:
          "Credential id must contain only alphanumeric characters, underscores, and hyphens.",
      }),
    });

    await expect(
      vpRequest("https://verify.example.com", "client-1", {
        credentials: [{ id: "bad id", format: "dc+sd-jwt", meta: {} }],
      }),
    ).rejects.toEqual({
      errorCode: "dcql_query.credentials",
      errorMessage:
        "Credential id must contain only alphanumeric characters, underscores, and hyphens.",
    });
  });

  it("vpSessionRequest surfaces verify-service 400 error body", async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      status: 400,
      json: async () => ({
        errorCode: "dcql_query.credentials",
        errorMessage:
          "Credential id must contain only alphanumeric characters, underscores, and hyphens.",
      }),
    });

    await expect(
      vpSessionRequest(
        "https://verify.example.com",
        { credentials: [{ id: "bad id", format: "dc+sd-jwt", meta: {} }] },
        "client-1",
      ),
    ).rejects.toEqual({
      errorCode: "dcql_query.credentials",
      errorMessage:
        "Credential id must contain only alphanumeric characters, underscores, and hyphens.",
    });
  });
});
