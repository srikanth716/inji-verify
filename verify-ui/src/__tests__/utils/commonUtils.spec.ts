import {
  calculateVerifiedClaims,
  calculateUnverifiedClaims,
  getCredentialType,
} from "../../utils/commonUtils";
import { claim, DcqlCredentialQuery, MatchingVc } from "../../types/data-types";

jest.mock("../../utils/i18n", () => ({
  getLanguageCodes: jest.fn(() => ["en"]),
}));

const buildClaim = (
  name: string,
  type: string,
  credentials: DcqlCredentialQuery[]
): claim => ({
  name,
  type,
  logo: "/assets/cert.png",
  dcqlQuery: { credentials },
});

const ldpVc = (credentialType: string) => ({
  type: ["VerifiableCredential", credentialType],
});

const matchingResult = (
  vc: object,
  vcStatus: MatchingVc["vcStatus"] = "SUCCESS"
): MatchingVc => ({ vc, vcStatus });

describe("commonUtils credential matching", () => {
  describe("getCredentialType", () => {
    test("returns non-VerifiableCredential type from ldp_vc type array", () => {
      expect(getCredentialType(ldpVc("InsuranceCredential"))).toBe(
        "InsuranceCredential"
      );
    });

    test("returns full IRI when wallet submits absolute type identifier", () => {
      const iri =
        "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential";
      expect(getCredentialType(ldpVc(iri))).toBe(iri);
    });

    test("returns vct from SD-JWT regularClaims", () => {
      expect(
        getCredentialType({
          regularClaims: { vct: "MockVerifiableCredential_SD_JWT" },
        })
      ).toBe("MockVerifiableCredential_SD_JWT");
    });
  });

  describe("calculateVerifiedClaims", () => {
    test("matches submitted credential against IRI type_values using # separator", () => {
      const selectedClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential",
              ],
            ],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(result).toHaveLength(1);
      expect(result[0].vcStatus).toBe("SUCCESS");
    });

    test("matches submitted credential against IRI type_values using / separator", () => {
      const selectedClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              ["https://example.org/context/InsuranceCredential"],
            ],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(result).toHaveLength(1);
    });

    test("matches relative configured type against submitted absolute IRI", () => {
      const selectedClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["InsuranceCredential"]],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [
          matchingResult(
            ldpVc(
              "https://example.org/context.json#InsuranceCredential"
            )
          ),
        ]
      );

      expect(result).toHaveLength(1);
    });

    test("matches when top-level claim type differs from dcql type_values", () => {
      const selectedClaim = buildClaim("Health Insurance", "HealthCredential", [
        {
          id: "health_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential",
              ],
            ],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(result).toHaveLength(1);
    });

    test("matches any credential definition within a multi-credential claim", () => {
      const selectedClaim = buildClaim(
        "MOSIP ID + Health Insurance",
        "MOSIPVerifiableCredential",
        [
          {
            id: "mosip_verifiable_credential_id",
            format: "ldp_vc",
            meta: {
              type_values: [
                [
                  "https://inji.github.io/inji-config/contexts/mosip-identity-context.json#MOSIPVerifiableCredential",
                ],
              ],
            },
          },
          {
            id: "health_insurance_credential_id",
            format: "ldp_vc",
            meta: {
              type_values: [
                [
                  "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential",
                ],
              ],
            },
          },
        ]
      );

      const mosipResult = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("MOSIPVerifiableCredential"))]
      );
      const insuranceResult = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(mosipResult).toHaveLength(1);
      expect(insuranceResult).toHaveLength(1);
    });

    test("matches when any configured type value in a type_values group matches", () => {
      const selectedClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://www.w3.org/2018/credentials#VerifiableCredential",
                "MOSIPVerifiableCredential",
              ],
            ],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("MOSIPVerifiableCredential"))]
      );

      expect(result).toHaveLength(1);
    });

    test("matches SD-JWT credentials using vct_values", () => {
      const selectedClaim = buildClaim(
        "Mock Identity (SD JWT)",
        "MockVerifiableCredential_SD_JWT",
        [
          {
            id: "mock_identity_sd_jwt_credential_id",
            format: "vc+sd-jwt",
            meta: {
              vct_values: ["MockVerifiableCredential_SD_JWT"],
            },
          },
        ]
      );

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [
          matchingResult({
            regularClaims: { vct: "MockVerifiableCredential_SD_JWT" },
          }),
        ]
      );

      expect(result).toHaveLength(1);
    });

    test("returns only selected claims that have matching submissions", () => {
      const insuranceClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential",
              ],
            ],
          },
        },
      ]);
      const mosipClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://inji.github.io/inji-config/contexts/mosip-identity-context.json#MOSIPVerifiableCredential",
              ],
            ],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [insuranceClaim, mosipClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(result).toHaveLength(1);
      expect(getCredentialType(result[0].vc)).toBe("InsuranceCredential");
    });

    test("prefers SUCCESS credential when multiple submissions share the same type", () => {
      const selectedClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["InsuranceCredential"]],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [
          matchingResult(ldpVc("InsuranceCredential"), "INVALID"),
          matchingResult(ldpVc("InsuranceCredential"), "SUCCESS"),
        ]
      );

      expect(result).toHaveLength(1);
      expect(result[0].vcStatus).toBe("SUCCESS");
    });

    test("returns empty when no configured type value matches submitted credential", () => {
      const selectedClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["MOSIPVerifiableCredential"]],
          },
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(result).toHaveLength(0);
    });

    test("does not match using top-level claim type when dcql type_values are absent", () => {
      const selectedClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {},
        },
      ]);

      const result = calculateVerifiedClaims(
        [selectedClaim],
        [matchingResult(ldpVc("MOSIPVerifiableCredential"))]
      );

      expect(result).toHaveLength(0);
    });
  });

  describe("calculateUnverifiedClaims", () => {
    test("returns claims with no matching submitted credential", () => {
      const insuranceClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["InsuranceCredential"]],
          },
        },
      ]);
      const mosipClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["MOSIPVerifiableCredential"]],
          },
        },
      ]);

      const unverified = calculateUnverifiedClaims(
        [insuranceClaim, mosipClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(unverified).toHaveLength(1);
      expect(unverified[0].name).toBe("MOSIP ID");
    });

    test("returns empty when every selected claim has a matching submission", () => {
      const insuranceClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["InsuranceCredential"]],
          },
        },
      ]);
      const mosipClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["MOSIPVerifiableCredential"]],
          },
        },
      ]);

      const unverified = calculateUnverifiedClaims(
        [insuranceClaim, mosipClaim],
        [
          matchingResult(ldpVc("InsuranceCredential")),
          matchingResult(ldpVc("MOSIPVerifiableCredential")),
        ]
      );

      expect(unverified).toHaveLength(0);
    });

    test("treats claim as verified when dcql type_values match even if top-level type differs", () => {
      const healthClaim = buildClaim("Health Insurance", "HealthCredential", [
        {
          id: "health_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [
              [
                "https://inji.github.io/inji-config/contexts/insurance-context.json#InsuranceCredential",
              ],
            ],
          },
        },
      ]);

      const unverified = calculateUnverifiedClaims(
        [healthClaim],
        [matchingResult(ldpVc("InsuranceCredential"))]
      );

      expect(unverified).toHaveLength(0);
    });

    test("returns all claims when no submissions match configured dcql type values", () => {
      const insuranceClaim = buildClaim("Life Insurance", "InsuranceCredential", [
        {
          id: "life_insurance_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["InsuranceCredential"]],
          },
        },
      ]);
      const mosipClaim = buildClaim("MOSIP ID", "MOSIPVerifiableCredential", [
        {
          id: "mosip_verifiable_credential_id",
          format: "ldp_vc",
          meta: {
            type_values: [["MOSIPVerifiableCredential"]],
          },
        },
      ]);

      const unverified = calculateUnverifiedClaims(
        [insuranceClaim, mosipClaim],
        [matchingResult(ldpVc("RegistrationReceiptCredential"))]
      );

      expect(unverified).toHaveLength(2);
    });
  });
});
