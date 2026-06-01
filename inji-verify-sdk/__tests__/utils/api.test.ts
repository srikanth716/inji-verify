import { vpSessionRequest } from "../../src/utils/api";

describe("vp request api errors", () => {
  beforeEach(() => {
    global.fetch = jest.fn();
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
