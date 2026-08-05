package io.inji.verify.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.dto.authorizationrequest.VPRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestStatusDto;
import io.inji.verify.dto.client.ClientMetadataDto;
import io.inji.verify.dto.core.ErrorDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.enums.VPRequestStatus;
import io.inji.verify.exception.JWTCreationException;
import io.inji.verify.exception.VPRequestNotFoundException;
import io.inji.verify.exception.VPRequestValidationException;
import io.inji.verify.models.AuthorizationRequestCreateResponse;
import io.inji.verify.models.VPSubmission;
import io.inji.verify.repository.AuthorizationRequestCreateResponseRepository;
import io.inji.verify.repository.VPSubmissionRepository;
import io.inji.verify.services.KeyManagementService;
import io.inji.verify.shared.Constants;
import io.inji.verify.services.VerifiablePresentationRequestService;
import io.inji.verify.utils.SecurityUtils;
import io.inji.verify.utils.Utils;
import io.inji.verify.utils.VerifierOriginResolver;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.async.DeferredResult;
import java.text.ParseException;
import java.util.regex.Pattern;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.NoSuchElementException;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import static io.inji.verify.shared.Constants.VP_FORMATS_SUPPORTED;

@Service
@Slf4j
public class VerifiablePresentationRequestServiceImpl implements VerifiablePresentationRequestService {

    final AuthorizationRequestCreateResponseRepository authorizationRequestCreateResponseRepository;
    final VPSubmissionRepository vpSubmissionRepository;
    final KeyManagementService<OctetKeyPair> keyManagementService;
    final ObjectMapper objectMapper;

    @Value("${inji.vp-request.long-polling-timeout}")
    Long defaultTimeout;

    @Value("${inji.vp-submission.base-url}")
    String verifyServiceBaseUrl;

    @Value("${inji.did.verify.public.key.uri}")
    String verifyPublicKeyURI;

    ConcurrentHashMap<String, DeferredResult<VPRequestStatusDto>> vpRequestStatusListeners = new ConcurrentHashMap<>();

    private static final Pattern NONCE_PATTERN = Pattern.compile("^[A-Za-z0-9\\-._~]{16,}$");

    public VerifiablePresentationRequestServiceImpl(
            AuthorizationRequestCreateResponseRepository authorizationRequestCreateResponseRepository,
            VPSubmissionRepository vpSubmissionRepository,
            KeyManagementService<OctetKeyPair> keyManagementService,
            ObjectMapper objectMapper) {
        this.authorizationRequestCreateResponseRepository = authorizationRequestCreateResponseRepository;
        this.vpSubmissionRepository = vpSubmissionRepository;
        this.keyManagementService = keyManagementService;
        this.objectMapper = objectMapper;
    }

    @Override
    public VPRequestResponseDto createAuthorizationRequest(VPRequestCreateDto vpRequestCreate, HttpServletRequest httpRequest) {
        log.info("Creating authorization request");
        String transactionId = vpRequestCreate.getTransactionId() != null ? vpRequestCreate.getTransactionId() : Utils.generateID(Constants.TRANSACTION_ID_PREFIX);
        String requestId = Utils.generateID(Constants.REQUEST_ID_PREFIX);
        long expiresAt = Instant.now().plusSeconds(Constants.DEFAULT_EXPIRY).toEpochMilli();
        String nonce;
        if (StringUtils.hasText(vpRequestCreate.getNonce())) {
            if (!NONCE_PATTERN.matcher(vpRequestCreate.getNonce()).matches()) {
                throw new VPRequestValidationException(ErrorCode.NONCE_INVALID);
            }
            nonce = vpRequestCreate.getNonce();
        } else {
            nonce = SecurityUtils.generateNonce();
        }

        String responseMode = resolveResponseMode(vpRequestCreate.getResponseMode());
        boolean isDcApi = Constants.RESPONSE_MODE_DC_API.equals(responseMode);
        List<String> expectedOrigins = null;
        String responseUri = null;

        if (isDcApi) {
            if (vpRequestCreate.getClientId() == null
                    || !vpRequestCreate.getClientId().startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER)) {
                throw new VPRequestValidationException(ErrorCode.DC_API_REQUIRES_DID_CLIENT_ID);
            }
            String verifierOrigin = VerifierOriginResolver.resolve(httpRequest)
                    .orElseThrow(() -> new VPRequestValidationException(ErrorCode.VERIFIER_ORIGIN_REQUIRED));
            expectedOrigins = List.of(verifierOrigin);
        } else {
            responseUri = verifyServiceBaseUrl + Constants.VP_RESPONSE_SUBMISSION_URI;
        }

        boolean responseCodeValidationRequired = vpRequestCreate.isResponseCodeValidationRequired();
        AuthorizationRequestResponseDto authorizationRequestResponseDto = new AuthorizationRequestResponseDto(
                vpRequestCreate.getClientId(),
                vpRequestCreate.getDcqlQuery(),
                null, // presentationDefinition is deprecated and should not be used, set to null for backward compatibility
                nonce,
                responseUri,
                false, //acceptVPWithoutHolderProof is deprecated and should not be used, set to false for backward compatibility
                responseCodeValidationRequired,
                responseMode,
                expectedOrigins
        );

        AuthorizationRequestCreateResponse authorizationRequestCreateResponse = new AuthorizationRequestCreateResponse(requestId, transactionId, authorizationRequestResponseDto, expiresAt);
        authorizationRequestCreateResponseRepository.save(authorizationRequestCreateResponse);
        log.info("Authorization request created with responseMode={}", responseMode);

        // DID and DC API both use request_uri / JWT fetch
        if (isDcApi || vpRequestCreate.getClientId().startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER)) {
            String requestUri = verifyServiceBaseUrl + Constants.VP_REQUEST_URI;
            return new VPRequestResponseDto(authorizationRequestCreateResponse.getTransactionId(), authorizationRequestCreateResponse.getRequestId(), null, authorizationRequestCreateResponse.getExpiresAt(), "%s/%s".formatted(requestUri, authorizationRequestCreateResponse.getRequestId()));
        }
        return new VPRequestResponseDto(authorizationRequestCreateResponse.getTransactionId(), authorizationRequestCreateResponse.getRequestId(), authorizationRequestCreateResponse.getAuthorizationDetails(), authorizationRequestCreateResponse.getExpiresAt(), null);
    }

    private String resolveResponseMode(String responseMode) {
        if (!StringUtils.hasText(responseMode)) {
            return Constants.RESPONSE_MODE;
        }
        if (Constants.RESPONSE_MODE.equals(responseMode) || Constants.RESPONSE_MODE_DC_API.equals(responseMode)) {
            return responseMode;
        }
        throw new VPRequestValidationException(ErrorCode.INVALID_RESPONSE_MODE);
    }

    @Override
    public VPRequestStatusDto getCurrentRequestStatus(String requestId) {
        VPSubmission vpSubmission = vpSubmissionRepository.findById(requestId).orElse(null);

        if (vpSubmission != null) {
            return new VPRequestStatusDto(VPRequestStatus.VP_SUBMITTED);
        }
        Long expiresAt = authorizationRequestCreateResponseRepository.findById(requestId).map(AuthorizationRequestCreateResponse::getExpiresAt).orElse(null);
        if (expiresAt == null) {
            return null;
        }
        if (Instant.now().toEpochMilli() > expiresAt) {
            return new VPRequestStatusDto(VPRequestStatus.EXPIRED);
        }
        return new VPRequestStatusDto(VPRequestStatus.ACTIVE);
    }

    @Override
    public List<String> getLatestRequestIdFor(String transactionId) {
        return authorizationRequestCreateResponseRepository.findAllByTransactionIdOrderByExpiresAtDesc(transactionId).stream().map(AuthorizationRequestCreateResponse::getRequestId).toList();
    }

    @Override
    public AuthorizationRequestCreateResponse getLatestAuthorizationRequestFor(String transactionId) {
        try {
            String requestId = getLatestRequestIdFor(transactionId).getFirst();
            return authorizationRequestCreateResponseRepository.findById(requestId).orElse(null);
        }catch (NoSuchElementException e){
            return null;
        }
    }

    private void registerVpRequestStatusListener(String requestId, DeferredResult<VPRequestStatusDto> result) {
        vpRequestStatusListeners.put(requestId, result);
    }

    @Override
    public void invokeVpRequestStatusListener(String requestId) {
        Optional.ofNullable(vpRequestStatusListeners.get(requestId)).ifPresent(vpRequestStatusDtoDeferredResult -> {
            vpRequestStatusDtoDeferredResult.setResult(new VPRequestStatusDto(VPRequestStatus.VP_SUBMITTED));
            vpRequestStatusListeners.remove(requestId);
        });
    }

    @Override
    public DeferredResult<VPRequestStatusDto> getStatus(String requestId) {
        return authorizationRequestCreateResponseRepository
                .findById(requestId)
                .map(authorizationRequestCreateResponse -> {
                    long expiresAt = authorizationRequestCreateResponse.getExpiresAt();
                    long timeToExpiry = expiresAt - Instant.now().toEpochMilli();
                    Long timeOut = timeToExpiry > defaultTimeout ? defaultTimeout : timeToExpiry;
                    DeferredResult<VPRequestStatusDto> result = new DeferredResult<>(timeOut);
                    VPRequestStatusDto currentRequestStatus = getCurrentRequestStatus(requestId);

                    if (currentRequestStatus.getStatus() == VPRequestStatus.EXPIRED) {
                        result.setResult(new VPRequestStatusDto(VPRequestStatus.EXPIRED));
                        return result;
                    }

                    if (currentRequestStatus.getStatus() == VPRequestStatus.VP_SUBMITTED) {
                        result.setResult(new VPRequestStatusDto(VPRequestStatus.VP_SUBMITTED));
                        return result;
                    }

                    result.onTimeout(() -> result.setResult(getCurrentRequestStatus(requestId)));
                    // cleanup on timeout
                    result.onTimeout(() -> {
                        vpRequestStatusListeners.remove(requestId);
                        result.setResult(getCurrentRequestStatus(requestId));
                    });

                    // cleanup on completion
                    result.onCompletion(() ->
                            vpRequestStatusListeners.remove(requestId)
                    );
                    
                    registerVpRequestStatusListener(requestId, result);
                    return result;
                })
                .orElseGet(() -> {
                    DeferredResult<VPRequestStatusDto> result = new DeferredResult<>();
                    result.setErrorResult(ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorDto(ErrorCode.NO_AUTH_REQUEST)));
                    return result;
                });
    }

    @Override
    public String getVPRequestJwt(String requestId) throws VPRequestNotFoundException {
        return authorizationRequestCreateResponseRepository
                .findById(requestId)
                .map(authorizationRequestCreateResponse -> {
                    AuthorizationRequestResponseDto details = authorizationRequestCreateResponse.getAuthorizationDetails();
                    String verifierDid = details.getClientId();
                    if (Constants.RESPONSE_MODE_DC_API.equals(details.getResponseMode())) {
                        return createAndSignAuthorizationDcApiRequestJwt(verifierDid, details);
                    }
                    String state = authorizationRequestCreateResponse.getRequestId();
                    return createAndSignAuthorizationRequestJwt(verifierDid, details, state);
                })
                .orElseThrow(VPRequestNotFoundException::new);
    }

    private String createAndSignAuthorizationRequestJwt(String verifierDid, AuthorizationRequestResponseDto authorizationRequest, String state) {

        try {
            String issuer = stripDidPrefix(verifierDid);
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .issueTime(Date.from(Instant.now()))
                    .claim("client_id", verifierDid)
                    .jwtID(UUID.randomUUID().toString())
                    .claim("response_type", authorizationRequest.getResponseType())
                    .claim("response_mode", Constants.RESPONSE_MODE)
                    .claim("nonce", authorizationRequest.getNonce())
                    .claim("state", state)
                    .claim("response_uri", authorizationRequest.getResponseUri());

            addClientMetadataIfDid(claimsBuilder, verifierDid);
            JWTClaimsSet claimsSet = addDcqlClaim(claimsBuilder.build(), authorizationRequest);
            return signAuthorizationRequestJwt(claimsSet);
        } catch (ParseException | JOSEException | JsonProcessingException e) {
            log.error("Error generating direct_post JWT: {}", e.getMessage());
            throw new JWTCreationException();
        }
    }

    private String createAndSignAuthorizationDcApiRequestJwt(String verifierDid, AuthorizationRequestResponseDto authorizationRequest) {
        try {
            String issuer = stripDidPrefix(verifierDid);
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .issueTime(Date.from(Instant.now()))
                    .claim("client_id", verifierDid)
                    .jwtID(UUID.randomUUID().toString())
                    .claim("response_type", authorizationRequest.getResponseType())
                    .claim("response_mode", Constants.RESPONSE_MODE_DC_API)
                    .claim("nonce", authorizationRequest.getNonce())
                    .claim("expected_origins", authorizationRequest.getExpectedOrigins());

            addClientMetadataIfDid(claimsBuilder, verifierDid);
            JWTClaimsSet claimsSet = addDcqlClaim(claimsBuilder.build(), authorizationRequest);
            return signAuthorizationRequestJwt(claimsSet);
        } catch (ParseException | JOSEException | JsonProcessingException e) {
            log.error("Error generating dc_api JWT: {}", e.getMessage());
            throw new JWTCreationException();
        }
    }

    private static String stripDidPrefix(String verifierDid) {
        return verifierDid != null
                ? verifierDid.replaceFirst("^" + Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER, "")
                : null;
    }

    private void addClientMetadataIfDid(JWTClaimsSet.Builder claimsBuilder, String verifierDid) {
        if (verifierDid != null && verifierDid.startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER)) {
            claimsBuilder.claim("client_metadata", new ClientMetadataDto(VP_FORMATS_SUPPORTED));
        }
    }

    private JWTClaimsSet addDcqlClaim(JWTClaimsSet claimsSet, AuthorizationRequestResponseDto authorizationRequest)
            throws JsonProcessingException, ParseException {
        if (authorizationRequest.getDcqlQuery() == null) {
            return claimsSet;
        }
        String dcqlQueryJson = objectMapper.writeValueAsString(authorizationRequest.getDcqlQuery());
        return new JWTClaimsSet.Builder(claimsSet)
                .claim("dcql_query", JSONObjectUtils.parse(dcqlQueryJson))
                .build();
    }

    private String signAuthorizationRequestJwt(JWTClaimsSet claimsSet) throws JOSEException {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("oauth-authz-req+jwt"))
                .keyID(verifyPublicKeyURI)
                .build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        JWSSigner signer = new Ed25519Signer(keyManagementService.getKeyPair());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
