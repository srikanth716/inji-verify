package io.inji.verify.services.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.dto.authorizationrequest.VPRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestStatusDto;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.exception.VPRequestNotFoundException;
import io.inji.verify.exception.VPRequestValidationException;
import com.nimbusds.jwt.SignedJWT;
import io.inji.verify.testsupport.DcqlTestFixtures;
import io.inji.verify.enums.VPRequestStatus;
import io.inji.verify.models.AuthorizationRequestCreateResponse;
import io.inji.verify.repository.AuthorizationRequestCreateResponseRepository;
import io.inji.verify.repository.VPSubmissionRepository;
import io.inji.verify.services.KeyManagementService;
import io.inji.verify.shared.Constants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.async.DeferredResult;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;

class VerifiablePresentationRequestServiceImplTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static VerifiablePresentationRequestServiceImpl service;
    static AuthorizationRequestCreateResponseRepository mockAuthorizationRequestCreateResponseRepository;
    static VPSubmissionRepository mockVPSubmissionRepository;
    static KeyManagementService<OctetKeyPair> mockKeyManagementService;

    private static DCQLQueryDto minimalDcqlQuery() throws Exception {
        return OBJECT_MAPPER.readValue(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"cred1\"]}}]}",
                DCQLQueryDto.class);
    }

    @BeforeAll
    public static void beforeAll() throws Exception {
        mockAuthorizationRequestCreateResponseRepository = mock(AuthorizationRequestCreateResponseRepository.class);
        mockVPSubmissionRepository = mock(VPSubmissionRepository.class);
        mockKeyManagementService = mock(KeyManagementService.class);
        service = new VerifiablePresentationRequestServiceImpl(
                mockAuthorizationRequestCreateResponseRepository,
                mockVPSubmissionRepository,
                mockKeyManagementService,
                OBJECT_MAPPER);
    }

    @Test
    public void shouldCreateNewAuthorizationRequest() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto vpRequestCreateDto = new VPRequestCreateDto(
                "test_client_id",
                "test_transaction_id",
                null,
                minimalDcqlQuery(),
                false);

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(vpRequestCreateDto, null);

        assertNotNull(responseDto);
        assertEquals("test_transaction_id", responseDto.getTransactionId());
        assertNotNull(responseDto.getRequestId());
        assertNotNull(responseDto.getAuthorizationDetails());
        assertTrue(responseDto.getExpiresAt() > Instant.now().toEpochMilli());
    }

    @Test
    public void shouldCreateAuthorizationRequestWithMissingTransactionId() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto vpRequestCreateDto = new VPRequestCreateDto(
                "test_client_id",
                null,
                null,
                minimalDcqlQuery(),
                false);

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(vpRequestCreateDto, null);

        assertNotNull(responseDto);
        assertTrue(responseDto.getTransactionId().startsWith(Constants.TRANSACTION_ID_PREFIX));
    }

    @Test
    public void shouldGetCurrentAuthorizationRequestStateForExistingRequest() {
        AuthorizationRequestCreateResponse mockResponse =
                new AuthorizationRequestCreateResponse("req_id", "tx_id", null, Instant.now().toEpochMilli() + 10000);
        when(mockAuthorizationRequestCreateResponseRepository.findById("req_id"))
                .thenReturn(java.util.Optional.of(mockResponse));
        when(mockVPSubmissionRepository.findById("req_id")).thenReturn(Optional.empty());

        VPRequestStatusDto vpRequestStatusDto = service.getCurrentRequestStatus("req_id");

        assertEquals(VPRequestStatus.ACTIVE, vpRequestStatusDto.getStatus());
    }

    @Test
    public void shouldGetCurrentAuthorizationRequestStateForNonexistentRequest() {
        when(mockVPSubmissionRepository.findById("req_id")).thenReturn(Optional.empty());
        AuthorizationRequestCreateResponse mockResponse =
                new AuthorizationRequestCreateResponse("req_id", "tx_id", null, Instant.now().toEpochMilli() + 10000);
        when(mockAuthorizationRequestCreateResponseRepository.findById("req_id"))
                .thenReturn(java.util.Optional.of(mockResponse));

        VPRequestStatusDto vpRequestStatusDto = service.getCurrentRequestStatus("nonexistent_id");

        assertNull(vpRequestStatusDto);
    }

    @Test
    void getStatus_requestIdNotFound_returnsNotFoundError() {
        when(mockAuthorizationRequestCreateResponseRepository.findById("req_id")).thenReturn(Optional.empty());

        DeferredResult<VPRequestStatusDto> result = service.getStatus("req_id");

        assertEquals(
                HttpStatus.NOT_FOUND,
                ((ResponseEntity<?>) Objects.requireNonNull(result.getResult())).getStatusCode());
    }

    @Test()
    void getStatus_requestExpired_returnsExpiredStatus() {
        service.defaultTimeout = 1000L;
        String requestId = "req_id";
        AuthorizationRequestCreateResponse response =
                new AuthorizationRequestCreateResponse("req_id", "tx_id", null, Instant.now().toEpochMilli() - 10000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(response));

        DeferredResult<VPRequestStatusDto> result = service.getStatus(requestId);

        assertEquals(
                VPRequestStatus.EXPIRED,
                ((VPRequestStatusDto) Objects.requireNonNull(result.getResult())).getStatus());
    }

    @Test
    @DisplayName("Should produce JWT when verifierDid is null (null issuer path)")
    void getVPRequestJwt_WithNullVerifierDid_ProducesJwt() throws Exception {
        String requestId = "req_null_did";
        AuthorizationRequestResponseDto authzDto =
                new AuthorizationRequestResponseDto(
                        null, // null clientId → verifierDid null
                        DcqlTestFixtures.minimalDcqlDto(),
                        null, "nonce", "https://resp.example/post", false, false, Constants.RESPONSE_MODE, null);
        AuthorizationRequestCreateResponse authzResponse =
                new AuthorizationRequestCreateResponse(requestId, "tx", authzDto, Instant.now().toEpochMilli() + 5000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(authzResponse));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String jwt = service.getVPRequestJwt(requestId);

        assertNotNull(jwt);
        // issuer should be null when verifierDid is null
        assertNull(SignedJWT.parse(jwt).getJWTClaimsSet().getIssuer());
    }

    @Test
    @DisplayName("JWT should include client_metadata when clientId starts with decentralized_identifier")
    void getVPRequestJwt_WithDecentralizedIdentifierDid_IncludesClientMetadata() throws Exception {
        String requestId = "req_dec_id";
        String did = "decentralized_identifier:did:example:verifier";
        AuthorizationRequestResponseDto authzDto =
                new AuthorizationRequestResponseDto(
                        did,
                        DcqlTestFixtures.minimalDcqlDto(),
                        null, "nonce", "https://resp.example/post", false, false, Constants.RESPONSE_MODE, null);
        AuthorizationRequestCreateResponse authzResponse =
                new AuthorizationRequestCreateResponse(requestId, "tx", authzDto, Instant.now().toEpochMilli() + 5000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(authzResponse));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String jwt = service.getVPRequestJwt(requestId);

        assertNotNull(jwt);
        var claims = SignedJWT.parse(jwt).getJWTClaimsSet();
        // The decentralized_identifier: prefix should be stripped for the issuer
        assertEquals("did:example:verifier", claims.getIssuer());
        // client_metadata claim should be present
        assertNotNull(claims.getClaim("client_metadata"));
    }

    @Test
    @DisplayName("Should return JWT string when authorization request and details are valid")
    void getVPRequestJwt_ValidRequest_ReturnsJwtString() throws Exception {
        String requestId = "testRequestId123";
        String verifierDid = "did:example:verifier123";
        String expectedJwtHeader = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EifQ.";

        AuthorizationRequestResponseDto authzDetailsDto =
                new AuthorizationRequestResponseDto(
                        verifierDid,
                        DcqlTestFixtures.minimalDcqlDto(),
                        null,
                        "nonce",
                        "https://verifier.example/resp",
                        false,
                        false, Constants.RESPONSE_MODE, null);

        AuthorizationRequestCreateResponse authzResponse =
                new AuthorizationRequestCreateResponse(requestId, null, authzDetailsDto, 0L);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(authzResponse));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();

        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String actualJwt = service.getVPRequestJwt(requestId);

        assertNotNull(actualJwt);
        assertTrue(actualJwt.startsWith(expectedJwtHeader));
        assertJwtContainsDcqlWithoutPresentationDefinition(actualJwt);

        verify(mockAuthorizationRequestCreateResponseRepository, times(1)).findById(requestId);
    }

    private static void assertJwtContainsDcqlWithoutPresentationDefinition(String jwt) throws ParseException {
        var claims = SignedJWT.parse(jwt).getJWTClaimsSet();
        assertNotNull(claims.getClaim("dcql_query"));
        assertNull(claims.getClaim("presentation_definition"));
        assertNull(claims.getClaim("presentation_definition_uri"));
    }

    @Test
    void getVPRequestJwt_NullAuthorizationDetails_Throws_VPRequestNotFoundException() {
        String requestId = "reqWithNullDetails";
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.empty());

        assertThrows(VPRequestNotFoundException.class, () -> service.getVPRequestJwt(requestId));
    }

    @Test
    void getVPRequestJwt_WhenDcqlMissing_ReturnsJwtWithoutDcqlClaim() throws Exception {
        String requestId = "reqMissingDcql";
        AuthorizationRequestResponseDto authzDto =
                new AuthorizationRequestResponseDto("did:example", null, null, "nonce", "responseUri", false, false, Constants.RESPONSE_MODE, null);
        AuthorizationRequestCreateResponse response =
                new AuthorizationRequestCreateResponse(requestId, "tx", authzDto, Instant.now().toEpochMilli() + 1000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(response));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String jwt = service.getVPRequestJwt(requestId);

        assertNotNull(jwt);
        assertNull(SignedJWT.parse(jwt).getJWTClaimsSet().getClaim("dcql_query"));
    }

    @Test
    void getStatus_WithTimeout_InvokesListener() {
        service.defaultTimeout = 100L;
        String requestId = "timeoutReq";
        AuthorizationRequestCreateResponse response =
                new AuthorizationRequestCreateResponse(
                        requestId,
                        "tx",
                        new AuthorizationRequestResponseDto(
                                "did:example", DcqlTestFixtures.minimalDcqlDto(), null, "nonce", "responseUri", false, false, Constants.RESPONSE_MODE, null),
                        Instant.now().toEpochMilli() + 2000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(response));

        DeferredResult<VPRequestStatusDto> result = service.getStatus(requestId);
        assertNotNull(result);
    }

    @Test
    void getVPRequestJwt_RequestNotFound_ThrowsException() {
        when(mockAuthorizationRequestCreateResponseRepository.findById("missingId")).thenReturn(Optional.empty());

        assertThrows(VPRequestNotFoundException.class, () -> service.getVPRequestJwt("missingId"));
    }

    @Test
    void should_omitStateAndResponseUri_andIncludeExpectedOrigins_when_dcApiMode() throws Exception {
        String requestId = "reqDcApi";
        String didClient = "decentralized_identifier:did:web:verify.example.com";
        AuthorizationRequestResponseDto authzDto =
                new AuthorizationRequestResponseDto(
                        didClient,
                        DcqlTestFixtures.minimalDcqlDto(),
                        null,
                        "nonce-value-123456",
                        null,
                        false,
                        false,
                        Constants.RESPONSE_MODE_DC_API,
                        List.of("https://verify.example.com"));
        AuthorizationRequestCreateResponse response =
                new AuthorizationRequestCreateResponse(requestId, "tx", authzDto, Instant.now().toEpochMilli() + 10000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(response));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String jwt = service.getVPRequestJwt(requestId);
        var claims = SignedJWT.parse(jwt).getJWTClaimsSet();

        assertEquals(Constants.RESPONSE_MODE_DC_API, claims.getStringClaim("response_mode"));
        assertEquals(List.of("https://verify.example.com"), claims.getStringListClaim("expected_origins"));
        assertNull(claims.getClaim("state"));
        assertNull(claims.getClaim("response_uri"));
        assertNotNull(claims.getClaim("dcql_query"));
        assertEquals(didClient, claims.getStringClaim("client_id"));
    }

    @Test
    void should_persistServerOrigin_when_dcApiRequest() throws Exception {
        clearInvocations(mockAuthorizationRequestCreateResponseRepository);
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String didClient = "decentralized_identifier:did:web:verify.example.com";
        VPRequestCreateDto dto = new VPRequestCreateDto(
                didClient,
                "tx1",
                "nonce-value-123456",
                minimalDcqlQuery(),
                false,
                Constants.RESPONSE_MODE_DC_API);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(dto, request);

        assertNotNull(responseDto.getRequestUri());
        assertNotNull(responseDto.getSubmissionUri());
        assertTrue(responseDto.getSubmissionUri().endsWith(Constants.VP_DC_API_SUBMISSION_URI),
                "submissionUri should end with '" + Constants.VP_DC_API_SUBMISSION_URI
                        + "' but was: " + responseDto.getSubmissionUri());
        ArgumentCaptor<AuthorizationRequestCreateResponse> captor =
                ArgumentCaptor.forClass(AuthorizationRequestCreateResponse.class);
        verify(mockAuthorizationRequestCreateResponseRepository, times(1)).save(captor.capture());
        AuthorizationRequestResponseDto details = captor.getValue().getAuthorizationDetails();
        assertEquals(Constants.RESPONSE_MODE_DC_API, details.getResponseMode());
        assertEquals(List.of("https://verify.example.com"), details.getExpectedOrigins());
        assertNull(details.getResponseUri());
    }

    @Test
    void should_throwDcApiRequiresDidClientId_when_clientIdIsNotDid() throws Exception {
        VPRequestCreateDto dto = new VPRequestCreateDto(
                "test_client_id",
                "tx1",
                "nonce-value-123456",
                minimalDcqlQuery(),
                false,
                Constants.RESPONSE_MODE_DC_API);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");

        VPRequestValidationException ex = assertThrows(VPRequestValidationException.class,
                () -> service.createAuthorizationRequest(dto, request));

        assertEquals(ErrorCode.DC_API_REQUIRES_DID_CLIENT_ID, ex.getErrorCode());
    }

    @Test
    void should_throwVerifierOriginRequired_when_originAndRefererMissing() throws Exception {
        String didClient = "decentralized_identifier:did:web:verify.example.com";
        VPRequestCreateDto dto = new VPRequestCreateDto(
                didClient,
                "tx1",
                "nonce-value-123456",
                minimalDcqlQuery(),
                false,
                Constants.RESPONSE_MODE_DC_API);

        MockHttpServletRequest request = new MockHttpServletRequest();

        VPRequestValidationException ex = assertThrows(VPRequestValidationException.class,
                () -> service.createAuthorizationRequest(dto, request));

        assertEquals(ErrorCode.VERIFIER_ORIGIN_REQUIRED, ex.getErrorCode());
    }

    @Test
    void should_useRefererOrigin_when_originHeaderAbsent() throws Exception {
        clearInvocations(mockAuthorizationRequestCreateResponseRepository);
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String didClient = "decentralized_identifier:did:web:verify.example.com";
        VPRequestCreateDto dto = new VPRequestCreateDto(
                didClient,
                "tx1",
                "nonce-value-123456",
                minimalDcqlQuery(),
                false,
                Constants.RESPONSE_MODE_DC_API);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "https://verify.example.com/verify");

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(dto, request);

        assertNotNull(responseDto.getRequestUri());
        ArgumentCaptor<AuthorizationRequestCreateResponse> captor =
                ArgumentCaptor.forClass(AuthorizationRequestCreateResponse.class);
        verify(mockAuthorizationRequestCreateResponseRepository, times(1)).save(captor.capture());
        assertEquals(List.of("https://verify.example.com"),
                captor.getValue().getAuthorizationDetails().getExpectedOrigins());
    }

    @Test
    void getVPRequestJwt_WithExpiredRequest_AllowsJwt() throws Exception {
        String requestId = "expiredReq";
        AuthorizationRequestResponseDto authzDto =
                new AuthorizationRequestResponseDto("did:example", DcqlTestFixtures.minimalDcqlDto(), null, "nonce", "responseUri", false, false, Constants.RESPONSE_MODE, null);
        AuthorizationRequestCreateResponse expiredResponse =
                new AuthorizationRequestCreateResponse(requestId, "tx", authzDto, Instant.now().toEpochMilli() - 5000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(expiredResponse));
        OctetKeyPair mockOKP = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        when(mockKeyManagementService.getKeyPair()).thenReturn(mockOKP);

        String jwt = service.getVPRequestJwt(requestId);
        assertNotNull(jwt);
    }

    @Test
    void getCurrentRequestStatus_WithExpiredRequest_ReturnsExpired() {
        String requestId = "expiredStatusReq";
        AuthorizationRequestCreateResponse expiredResponse =
                new AuthorizationRequestCreateResponse(requestId, "tx", null, Instant.now().toEpochMilli() - 1000);
        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(expiredResponse));
        when(mockVPSubmissionRepository.findById(requestId)).thenReturn(Optional.empty());

        VPRequestStatusDto status = service.getCurrentRequestStatus(requestId);

        assertEquals(VPRequestStatus.EXPIRED, status.getStatus());
    }

    @Test
    void shouldReturnStatusCompletedWhenSubmissionExists() {
        String requestId = "req_with_submission";
        AuthorizationRequestCreateResponse response =
                new AuthorizationRequestCreateResponse(requestId, "tx_id", null, Instant.now().toEpochMilli() + 10000);

        when(mockAuthorizationRequestCreateResponseRepository.findById(requestId)).thenReturn(Optional.of(response));
        when(mockVPSubmissionRepository.findById(requestId)).thenReturn(Optional.of(mock()));

        VPRequestStatusDto result = service.getCurrentRequestStatus(requestId);

        assertNotNull(result);
        assertEquals(VPRequestStatus.VP_SUBMITTED, result.getStatus());
    }

    @Test
    public void shouldCreateNewAuthorizationRequestWithResponseCodeValidationRequired() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto vpRequestCreateDto = new VPRequestCreateDto(
                "test_client_id",
                "test_transaction_id",
                null,
                minimalDcqlQuery(),
                true);

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(vpRequestCreateDto, null);

        assertNotNull(responseDto);
        assertEquals("test_transaction_id", responseDto.getTransactionId());
        assertNotNull(responseDto.getRequestId());
        assertNotNull(responseDto.getAuthorizationDetails());
        assertTrue(responseDto.getAuthorizationDetails().isResponseCodeValidationRequired());
        assertTrue(responseDto.getExpiresAt() > Instant.now().toEpochMilli());
    }

    @Test
    void shouldUseProvidedNonce_whenValidNonceSupplied() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);
        String validNonce = "abcABC123-._~valid";  // 18 chars, all URL-safe

        VPRequestCreateDto dto = new VPRequestCreateDto("client", "tx", validNonce, minimalDcqlQuery(), false);

        VPRequestResponseDto response = service.createAuthorizationRequest(dto, null);

        assertEquals(validNonce, response.getAuthorizationDetails().getNonce());
    }

    @Test
    void shouldGenerateNonce_whenNonceIsNull() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto dto = new VPRequestCreateDto("client", "tx", null, minimalDcqlQuery(), false);

        VPRequestResponseDto response = service.createAuthorizationRequest(dto, null);

        assertNotNull(response.getAuthorizationDetails().getNonce());
        assertFalse(response.getAuthorizationDetails().getNonce().isBlank());
    }

    @Test
    void shouldGenerateNonce_whenNonceIsBlank() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto dto = new VPRequestCreateDto("client", "tx", "   ", minimalDcqlQuery(), false);

        VPRequestResponseDto response = service.createAuthorizationRequest(dto, null);

        // blank nonce must NOT be used — a generated nonce must replace it
        assertNotNull(response.getAuthorizationDetails().getNonce());
        assertFalse(response.getAuthorizationDetails().getNonce().isBlank());
        assertNotEquals("   ", response.getAuthorizationDetails().getNonce());
    }

    @Test
    void shouldCreateAuthorizationRequest_WithDecentralizedIdentifierClientId() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto dto = new VPRequestCreateDto(
                "decentralized_identifier:did:example:verifier",
                "tx_dec_id", null, minimalDcqlQuery(), false);

        VPRequestResponseDto response = service.createAuthorizationRequest(dto, null);

        assertNotNull(response);
        assertEquals("tx_dec_id", response.getTransactionId());
        // DID-based flow: requestUri is populated, authorizationDetails is null
        assertNull(response.getAuthorizationDetails());
        assertNull(response.getSubmissionUri());
        String requestUri = response.getRequestUri();
        assertNotNull(requestUri);
        // URI must embed the VP request path defined in Constants
        assertTrue(requestUri.contains(Constants.VP_REQUEST_URI),
                "requestUri should contain the VP request path '" + Constants.VP_REQUEST_URI + "' but was: " + requestUri);
        // URI must end with the actual requestId so the wallet can fetch the signed JWT
        String requestId = response.getRequestId();
        assertTrue(requestUri.endsWith("/" + requestId),
                "requestUri should end with '/" + requestId + "' but was: " + requestUri);
        // requestId must follow the expected prefix convention
        assertTrue(requestId.startsWith(Constants.REQUEST_ID_PREFIX),
                "requestId should start with '" + Constants.REQUEST_ID_PREFIX + "' but was: " + requestId);
    }

    @Test
    void shouldFail_whenNonceContainsDisallowedCharacters() throws Exception {
        VPRequestCreateDto dto = new VPRequestCreateDto("client", "tx", "invalid nonce value!", minimalDcqlQuery(), false);

        VPRequestValidationException ex = assertThrows(VPRequestValidationException.class,
                () -> service.createAuthorizationRequest(dto, null));

        assertEquals(ErrorCode.NONCE_INVALID, ex.getErrorCode());
    }

    @Test
    void shouldFail_whenNonceIsTooShort() throws Exception {
        VPRequestCreateDto dto = new VPRequestCreateDto("client", "tx", "short", minimalDcqlQuery(), false);

        VPRequestValidationException ex = assertThrows(VPRequestValidationException.class,
                () -> service.createAuthorizationRequest(dto, null));

        assertEquals(ErrorCode.NONCE_INVALID, ex.getErrorCode());
    }

    @Test
    public void shouldCreateNewAuthorizationRequestWithPresentationFlowCrossDevice() throws Exception {
        when(mockAuthorizationRequestCreateResponseRepository.save(any(AuthorizationRequestCreateResponse.class)))
                .thenReturn(null);

        VPRequestCreateDto vpRequestCreateDto = new VPRequestCreateDto(
                "test_client_id",
                "test_transaction_id",
                null,
                minimalDcqlQuery(),
                false);

        VPRequestResponseDto responseDto = service.createAuthorizationRequest(vpRequestCreateDto, null);

        assertNotNull(responseDto);
        assertEquals("test_transaction_id", responseDto.getTransactionId());
        assertNotNull(responseDto.getRequestId());
        assertNotNull(responseDto.getAuthorizationDetails());
        assertFalse(responseDto.getAuthorizationDetails().isResponseCodeValidationRequired());
        assertTrue(responseDto.getExpiresAt() > Instant.now().toEpochMilli());
    }
}
