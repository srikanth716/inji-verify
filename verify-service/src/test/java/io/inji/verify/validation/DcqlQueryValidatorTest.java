package io.inji.verify.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.enums.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DcqlQueryValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode parse(String json) throws Exception {
        return MAPPER.readTree(json);
    }

    @Test
    void acceptsMinimalSdJwtCredentialWithEmptyMeta() throws Exception {
        assertNull(DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred-1\",\"format\":\"dc+sd-jwt\",\"meta\":{}}]}")));
    }

    @Test
    void acceptsCredentialWithClaimsClaimSetsAndCredentialSets() throws Exception {
        assertNull(DcqlQueryValidator.validate(parse("""
                {
                  "credentials": [
                    {
                      "id": "cred-1",
                      "format": "vc+sd-jwt",
                      "meta": { "vct_values": ["IdentityCredential"] },
                      "multiple": false,
                      "require_cryptographic_holder_binding": true,
                      "trusted_authorities": [
                        { "type": "aki", "values": ["issuer-1"] }
                      ],
                      "claims": [
                        { "id": "age_over_18", "path": ["age_over_18"] },
                        { "id": "birth_date", "path": ["birth_date"] }
                      ],
                      "claim_sets": [
                        ["age_over_18"],
                        ["birth_date"]
                      ]
                    }
                  ],
                  "credential_sets": [
                    { "options": [["cred-1"]], "required": true }
                  ]
                }
                """)));
    }

    @Test
    void acceptsJsonPathWithNullArraySelector() throws Exception {
        assertNull(DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{},"
                        + "\"claims\":[{\"path\":[\"names\",null,\"given_name\"]}]}]}")));
    }

    @Test
    void rejectsMissingCredentials() throws Exception {
        assertEquals(ErrorCode.DCQL_CREDENTIALS_REQUIRED,
                DcqlQueryValidator.validate(parse("{}")));
    }

    @Test
    void rejectsInvalidCredentialIdCharacters() throws Exception {
        assertEquals(ErrorCode.DCQL_CREDENTIAL_ID_INVALID, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred 1\",\"format\":\"dc+sd-jwt\",\"meta\":{}}]}")));
    }

    @Test
    void rejectsDuplicateCredentialIds() throws Exception {
        assertEquals(ErrorCode.DCQL_DUPLICATE_CREDENTIAL_ID, DcqlQueryValidator.validate(parse("""
                {
                  "credentials": [
                    { "id": "cred-1", "format": "dc+sd-jwt", "meta": {} },
                    { "id": "cred-1", "format": "dc+sd-jwt", "meta": {} }
                  ]
                }
                """)));
    }

    @Test
    void rejectsUnsupportedFormat() throws Exception {
        assertEquals(ErrorCode.DCQL_CREDENTIAL_FORMAT_UNSUPPORTED, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"ldp_vc\",\"meta\":{}}]}")));
    }

    @Test
    void rejectsMissingMeta() throws Exception {
        assertEquals(ErrorCode.DCQL_META_REQUIRED, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\"}]}")));
    }

    @Test
    void rejectsInvalidVctValuesStructure() throws Exception {
        assertEquals(ErrorCode.INVALID_META_STRUCTURE, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"\"]}}]}")));
    }

    @Test
    void rejectsMdocWithoutDoctypeValue() throws Exception {
        assertEquals(ErrorCode.DCQL_DOCTYPE_VALUE_REQUIRED, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"mdoc1\",\"format\":\"mso_mdoc\",\"meta\":{}}]}")));
    }

    @Test
    void acceptsMdocWithDoctypeValue() throws Exception {
        assertNull(DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"mdoc1\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"org.iso.18013.5.1.mDL\"},"
                        + "\"claims\":[{\"path\":[\"org.iso.18013.5.1\",\"first_name\"]}]}]}")));
    }

    @Test
    void rejectsClaimWithoutPath() throws Exception {
        assertEquals(ErrorCode.INVALID_CLAIMS_STRUCTURE, DcqlQueryValidator.validate(parse(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{},\"claims\":[{}]}]}")));
    }

    @Test
    void rejectsClaimSetsWithoutClaimIds() throws Exception {
        assertEquals(ErrorCode.DCQL_CLAIM_ID_REQUIRED, DcqlQueryValidator.validate(parse("""
                {
                  "credentials": [{
                    "id": "cred1",
                    "format": "dc+sd-jwt",
                    "meta": {},
                    "claims": [{ "path": ["age_over_18"] }],
                    "claim_sets": [["age_over_18"]]
                  }]
                }
                """)));
    }

    @Test
    void rejectsUnknownClaimIdInClaimSets() throws Exception {
        assertEquals(ErrorCode.INVALID_CLAIM_SETS_STRUCTURE, DcqlQueryValidator.validate(parse("""
                {
                  "credentials": [{
                    "id": "cred1",
                    "format": "dc+sd-jwt",
                    "meta": {},
                    "claims": [{ "id": "age_over_18", "path": ["age_over_18"] }],
                    "claim_sets": [["birth_date"]]
                  }]
                }
                """)));
    }

    @Test
    void rejectsInvalidCredentialSetsReference() throws Exception {
        assertEquals(ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE, DcqlQueryValidator.validate(parse("""
                {
                  "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }],
                  "credential_sets": [{ "options": [["missing-id"]] }]
                }
                """)));
    }
}
