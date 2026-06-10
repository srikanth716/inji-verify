package io.inji.verify.validator;

import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.dcql.ClaimQueryDto;
import io.inji.verify.dto.dcql.CredentialMetaDto;
import io.inji.verify.dto.dcql.CredentialQueryDto;
import io.inji.verify.dto.dcql.CredentialSetQueryDto;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import io.inji.verify.dto.result.DcqlTokensDto;
import io.inji.verify.dto.result.ValidationResult;
import io.mosip.pixelpass.PixelPass;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class DcqlResponseValidatorTest {

    @Mock
    private PixelPass pixelPass;

    private DcqlResponseValidator dcqlResponseValidator;

    @BeforeEach
    void setUp() {
        dcqlResponseValidator = new DcqlResponseValidator(
                List.of("_sd", "_sd_alg", "iss", "cnf", "sub", "aud", "exp", "nbf", "iat", "cti"),
                pixelPass);
    }

    private static CredentialQueryDto sdJwtCredential(
            String id, String vct, List<ClaimQueryDto> claims, List<List<String>> claimSets, boolean multiple) {
        return new CredentialQueryDto(
                id,
                "vc+sd-jwt",
                new CredentialMetaDto(List.of(vct), null),
                true,
                multiple,
                claims,
                claimSets);
    }

    private static String testSdJwt(String typ, String vct) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"typ\":\"" + typ + "\",\"alg\":\"none\"}").getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"vct\":\"" + vct + "\"}").getBytes());
        return header + "." + payload + ".signature";
    }

    private static DcqlTokensDto sdJwtTokens(Map<String, List<String>> tokens) {
        return new DcqlTokensDto(new HashMap<>(), new HashMap<>(), tokens);
    }

    private static JSONObject ldpVpWithSubject(Map<String, Object> subjectClaims) {
        JSONObject subject = new JSONObject(subjectClaims);
        return new JSONObject()
                .put("type", new JSONArray().put("VerifiablePresentation"))
                .put("verifiableCredential", new JSONArray().put(new JSONObject()
                        .put("type", new JSONArray().put("VerifiableCredential"))
                        .put("credentialSubject", subject)));
    }

    @Test
    void shouldIgnoreUnknownCredentialId_whenKnownCredentialIsValid() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(Map.of(
                "wrong_query_id", List.of(testSdJwt("vc+sd-jwt", "ignored.vct")),
                "student_id_credential_query", List.of(testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
        assertNull(result.message());
    }

    @Test
    void shouldReturnSpecificError_whenRequiredCredentialMissingFromSubmission() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        ValidationResult result = dcqlResponseValidator.validate(
                auth, new DcqlTokensDto(new HashMap<>(), new HashMap<>(), new HashMap<>()));

        assertFalse(result.valid());
        assertTrue(result.message().contains("student_id_credential_query"));
        assertTrue(result.message().contains("was not included in vp_token"));
    }

    @Test
    void shouldReturnSpecificError_whenSdJwtFormatMismatch() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("student_id_credential_query", List.of(testSdJwt("dc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("requires format vc+sd-jwt"));
        assertTrue(result.message().contains("dc+sd-jwt"));
    }

    @Test
    void shouldRejectSubmission_whenTypMismatchAndRequiredClaimMissing() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "did:web:injiverify.dev-int-inji.mosip.net:v1:verify",
                new DCQLQueryDto(List.of(new CredentialQueryDto(
                        "student_id_credential_query",
                        "dc+sd-jwt",
                        new CredentialMetaDto(List.of("student_id_credential"), null),
                        true,
                        false,
                        List.of(new ClaimQueryDto("first_name", List.of("first_name"), null)),
                        null)), null),
                null, "MTc3OTEwMTI1ODkzOQ==", "https://injiverify.dev-int-inji.mosip.net/v1/verify/v2/vp-submission/direct-post",
                true, false);

        String token = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJub25lIn0.eyJ2Y3QiOiJzdHVkZW50X2lkX2NyZWRlbnRpYWwifQ.sig";
        DcqlTokensDto tokens = sdJwtTokens(Map.of("student_id_credential_query", List.of(token)));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("dc+sd-jwt"));
        assertTrue(result.message().contains("vc+sd-jwt"));
    }

    @Test
    void shouldReturnSpecificError_whenVctDoesNotMatch() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("student_id_credential_query", List.of(testSdJwt("vc+sd-jwt", "wrong.vct.value"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("vct 'wrong.vct.value'"));
        assertTrue(result.message().contains("vct_values"));
    }

    @Test
    void shouldReturnSpecificError_whenRequiredCredentialSetNotSatisfied() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(
                                new CredentialQueryDto(
                                        "age_credential_query",
                                        "ldp_vc",
                                        new CredentialMetaDto(null, List.of("AgeCredential")),
                                        true,
                                        false,
                                        null,
                                        null),
                                sdJwtCredential(
                                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)),
                        List.of(new CredentialSetQueryDto(
                                List.of(List.of("age_credential_query", "student_id_credential_query")),
                                true))),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("student_id_credential_query", List.of(testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("age_credential_query"));
        assertTrue(result.message().contains("was not included in vp_token"));
    }

    @Test
    void shouldReturnClaimError_whenSubmittedCredentialFailsClaimCheckWithinCredentialSet() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(new CredentialQueryDto(
                                "age_credential_query",
                                "ldp_vc",
                                new CredentialMetaDto(null, List.of("VerifiableCredential")),
                                true,
                                false,
                                List.of(new ClaimQueryDto("first_name", List.of("credentialSubject", "first_name"), null)),
                                null)),
                        List.of(new CredentialSetQueryDto(List.of(List.of("age_credential_query")), true))),
                null, "nonce", "responseUri", false, false);

        JSONObject vp = ldpVpWithSubject(Map.of());

        DcqlTokensDto tokens = new DcqlTokensDto(
                Map.of("age_credential_query", List.of(vp)),
                new HashMap<>(),
                new HashMap<>());

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("first_name"));
        assertTrue(result.message().contains("was not found"));
    }

    @Test
    void shouldReturnSatisfied_whenSubmissionMatchesDcqlQuery() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("student_id_credential_query", List.of(testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
        assertNull(result.message());
    }

    @Test
    void shouldSatisfyClaimSets_whenAnyOptionMatches() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(new CredentialQueryDto(
                                "age_credential_query",
                                "ldp_vc",
                                new CredentialMetaDto(null, List.of("VerifiableCredential")),
                                true,
                                false,
                                List.of(
                                        new ClaimQueryDto("first_name", List.of("credentialSubject", "first_name"), null),
                                        new ClaimQueryDto("last_name", List.of("credentialSubject", "last_name"), null),
                                        new ClaimQueryDto("given_name", List.of("credentialSubject", "given_name"), null)),
                                List.of(
                                        List.of("first_name", "last_name"),
                                        List.of("given_name")))),
                        null),
                null, "nonce", "responseUri", false, false);

        JSONObject vp = ldpVpWithSubject(Map.of("given_name", "Ada"));

        DcqlTokensDto tokens = new DcqlTokensDto(
                Map.of("age_credential_query", List.of(vp)),
                new HashMap<>(),
                new HashMap<>());

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
    }

    @Test
    void shouldReject_whenNoClaimSetOptionMatches() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(new CredentialQueryDto(
                                "age_credential_query",
                                "ldp_vc",
                                new CredentialMetaDto(null, List.of("VerifiableCredential")),
                                true,
                                false,
                                List.of(
                                        new ClaimQueryDto("first_name", List.of("credentialSubject", "first_name"), null),
                                        new ClaimQueryDto("last_name", List.of("credentialSubject", "last_name"), null),
                                        new ClaimQueryDto("given_name", List.of("credentialSubject", "given_name"), null)),
                                List.of(
                                        List.of("first_name", "last_name"),
                                        List.of("given_name")))),
                        null),
                null, "nonce", "responseUri", false, false);

        JSONObject vp = ldpVpWithSubject(Map.of("first_name", "Ada"));

        DcqlTokensDto tokens = new DcqlTokensDto(
                Map.of("age_credential_query", List.of(vp)),
                new HashMap<>(),
                new HashMap<>());

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("claim_sets"));
    }

    @Test
    void shouldDiscardInvalidPresentations_whenMultipleIsTrue() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, true)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(Map.of(
                "student_id_credential_query", List.of(
                        testSdJwt("dc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"),
                        testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
    }

    @Test
    void shouldReject_whenMultipleIsFalseButMultiplePresentationsSubmitted() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, false)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(Map.of(
                "student_id_credential_query", List.of(
                        testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"),
                        testSdJwt("vc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("requires a single presentation"));
    }

    @Test
    void shouldReject_whenMultipleIsTrueButAllPresentationsInvalid() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(List.of(sdJwtCredential(
                        "student_id_credential_query", "eu.europa.ec.eudi.msisdn.1", null, null, true)), null),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(Map.of(
                "student_id_credential_query", List.of(
                        testSdJwt("dc+sd-jwt", "eu.europa.ec.eudi.msisdn.1"),
                        testSdJwt("dc+sd-jwt", "wrong.vct.value"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("student_id_credential_query"));
    }

    @Test
    void shouldPass_whenOptionalCredentialSetIsNotSatisfied() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(
                                sdJwtCredential("required_cred", "required.vct", null, null, false),
                                sdJwtCredential("optional_cred", "optional.vct", null, null, false)),
                        List.of(
                                new CredentialSetQueryDto(List.of(List.of("required_cred")), true),
                                new CredentialSetQueryDto(List.of(List.of("optional_cred")), false))),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("required_cred", List.of(testSdJwt("vc+sd-jwt", "required.vct"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
    }

    @Test
    void shouldReject_whenClaimValueFilterDoesNotMatch() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(new CredentialQueryDto(
                                "age_credential_query",
                                "ldp_vc",
                                new CredentialMetaDto(null, List.of("VerifiableCredential")),
                                true,
                                false,
                                List.of(new ClaimQueryDto(
                                        "age", List.of("credentialSubject", "age"), List.of(18))),
                                null)),
                        null),
                null, "nonce", "responseUri", false, false);

        JSONObject vp = ldpVpWithSubject(Map.of("age", 21));

        DcqlTokensDto tokens = new DcqlTokensDto(
                Map.of("age_credential_query", List.of(vp)),
                new HashMap<>(),
                new HashMap<>());

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertFalse(result.valid());
        assertTrue(result.message().contains("does not match required values"));
    }

    @Test
    void shouldSatisfyCredentialSet_whenOrOptionMatches() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "clientId",
                new DCQLQueryDto(
                        List.of(
                                sdJwtCredential("age_sdjwt", "age.vct", null, null, false),
                                new CredentialQueryDto(
                                        "age_ldp",
                                        "ldp_vc",
                                        new CredentialMetaDto(null, List.of("VerifiableCredential")),
                                        true,
                                        false,
                                        null,
                                        null)),
                        List.of(new CredentialSetQueryDto(
                                List.of(List.of("age_sdjwt"), List.of("age_ldp")),
                                true))),
                null, "nonce", "responseUri", false, false);

        DcqlTokensDto tokens = sdJwtTokens(
                Map.of("age_sdjwt", List.of(testSdJwt("vc+sd-jwt", "age.vct"))));

        ValidationResult result = dcqlResponseValidator.validate(auth, tokens);

        assertTrue(result.valid());
    }
}
