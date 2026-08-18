package io.inji.verify.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.dto.authorizationrequest.VPRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestStatusDto;
import io.inji.verify.dto.client.ClientMetadataDto;
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
import io.inji.verify.validator.DcqlValidator;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.async.DeferredResult;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static io.inji.verify.shared.Constants.VP_FORMATS_SUPPORTED;

@Service
@Slf4j
public class VerifiablePresentationRequestServiceImpl implements VerifiablePresentationRequestService {

    final AuthorizationRequestCreateResponseRepository authorizationRequestCreateResponseRepository;
    final VPSubmissionRepository vpSubmissionRepository;
    final KeyManagementService<OctetKeyPair> keyManagementService;
    final ObjectMapper objectMapper;
    final DcqlValidator dcqlValidator;
    final ResourceLoader resourceLoader;

    @Value("${inji.vp-request.long-polling-timeout}")
    Long defaultTimeout;

    @Value("${inji.vp-submission.base-url}")
    String verifyServiceBaseUrl;

    @Value("${inji.did.verify.public.key.uri}")
    String verifyPublicKeyURI;

    @Value("${inji.jwt.signature-key-reference-type:kid}")
    String signatureKeyReferenceType;

    @Value("${inji.keystore.x5c.file.path:${inji.keystore.file.path}}")
    String x5cKeystorePath;

    @Value("${inji.keystore.x5c.file.pass:${inji.keystore.file.pass}}")
    String x5cKeystorePassword;

    ConcurrentHashMap<String, DeferredResult<VPRequestStatusDto>> vpRequestStatusListeners = new ConcurrentHashMap<>();

    private static final Pattern NONCE_PATTERN = Pattern.compile("^[A-Za-z0-9\\-._~]{16,}$");

    public VerifiablePresentationRequestServiceImpl(
            AuthorizationRequestCreateResponseRepository authorizationRequestCreateResponseRepository,
            VPSubmissionRepository vpSubmissionRepository,
            KeyManagementService<OctetKeyPair> keyManagementService,
            ObjectMapper objectMapper,
            DcqlValidator dcqlValidator,
            ResourceLoader resourceLoader) {
        this.authorizationRequestCreateResponseRepository = authorizationRequestCreateResponseRepository;
        this.vpSubmissionRepository = vpSubmissionRepository;
        this.keyManagementService = keyManagementService;
        this.objectMapper = objectMapper;
        this.dcqlValidator = dcqlValidator;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    void logJwtSigningConfiguration() {
        log.info("VP request JWT signing: referenceType={}, x5cKeystore={}", signatureKeyReferenceType, x5cKeystorePath);
    }

    @Override
    public VPRequestResponseDto createAuthorizationRequest(VPRequestCreateDto vpRequestCreate, HttpServletRequest httpRequest) {
        log.info("Creating authorization request");
        dcqlValidator.validate(vpRequestCreate.getDcqlQuery());
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
        boolean responseCodeValidationRequired = vpRequestCreate.isResponseCodeValidationRequired();
        String responseMode = StringUtils.hasText(vpRequestCreate.getResponseMode())
                ? vpRequestCreate.getResponseMode()
                : Constants.RESPONSE_MODE_DIRECT_POST;
        if (!Constants.RESPONSE_MODE_DIRECT_POST.equals(responseMode)
                && !Constants.RESPONSE_MODE_DC_API.equals(responseMode)) {
            throw new VPRequestValidationException(ErrorCode.INVALID_RESPONSE_MODE);
        }

        boolean isDcApi = Constants.RESPONSE_MODE_DC_API.equals(responseMode);
        List<String> expectedOrigins = null;
        String responseUri;
        if (isDcApi) {
            if (responseCodeValidationRequired) {
                throw new VPRequestValidationException(ErrorCode.DC_API_RESPONSE_CODE_NOT_SUPPORTED);
            }
            if (vpRequestCreate.getClientId() == null || !vpRequestCreate.getClientId().startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER)) {
                throw new VPRequestValidationException(ErrorCode.DC_API_REQUIRES_DID_CLIENT_ID);
            }
            String verifierOrigin = VerifierOriginResolver.resolve(httpRequest)
                    .orElseThrow(() -> new VPRequestValidationException(ErrorCode.VERIFIER_ORIGIN_REQUIRED));
            expectedOrigins = List.of(verifierOrigin);
            responseUri = verifyServiceBaseUrl + Constants.VP_DC_API_SUBMISSION_URI;
        } else {
            responseUri = verifyServiceBaseUrl + Constants.VP_DIRECT_POST_SUBMISSION_URI;
        }

        AuthorizationRequestResponseDto authorizationRequestResponseDto = new AuthorizationRequestResponseDto(
                vpRequestCreate.getClientId(),
                vpRequestCreate.getDcqlQuery(),
                null,
                nonce,
                responseUri,
                false,
                responseCodeValidationRequired,
                responseMode,
                expectedOrigins
        );

        AuthorizationRequestCreateResponse authorizationRequestCreateResponse = new AuthorizationRequestCreateResponse(requestId, transactionId, authorizationRequestResponseDto, expiresAt);
        authorizationRequestCreateResponseRepository.save(authorizationRequestCreateResponse);
        log.info("Authorization request created with responseMode={}", responseMode);

        String clientId = vpRequestCreate.getClientId();
        boolean isDidClient = clientId != null && clientId.startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER);
        if (isDcApi || isDidClient) {
            String requestUri = verifyServiceBaseUrl + Constants.VP_REQUEST_URI + "/" + requestId;
            return new VPRequestResponseDto(transactionId, requestId, null, expiresAt, requestUri, isDcApi ? responseUri : null);
        }
        return new VPRequestResponseDto(transactionId, requestId, authorizationRequestResponseDto, expiresAt, null, null);
    }

    @Override
    public VPRequestStatusDto getCurrentRequestStatus(String requestId) {
        if (vpSubmissionRepository.findById(requestId).isPresent()) {
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
                    result.setErrorResult(new VPRequestNotFoundException());
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
                    String state = authorizationRequestCreateResponse.getRequestId();
                    return createAndSignAuthorizationRequestJwt(verifierDid, authorizationRequestCreateResponse.getAuthorizationDetails(), state);
                })
                .orElseThrow(VPRequestNotFoundException::new);
    }

    private String createAndSignAuthorizationRequestJwt(String verifierDid, AuthorizationRequestResponseDto authorizationRequest, String state) {

        try {
            String issuer = verifierDid != null ? verifierDid.replaceFirst("^" + Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER, "") : null;
            boolean isDcApi = Constants.RESPONSE_MODE_DC_API.equals(authorizationRequest.getResponseMode());

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .issueTime(Date.from(Instant.now()))
                    .claim("client_id", verifierDid)
                    .jwtID(UUID.randomUUID().toString())
                    .claim("response_type", authorizationRequest.getResponseType())
                    .claim("response_mode", authorizationRequest.getResponseMode())
                    .claim("nonce", authorizationRequest.getNonce());

            if (isDcApi) {
                claimsBuilder.claim("expected_origins", authorizationRequest.getExpectedOrigins());
            } else {
                claimsBuilder
                        .claim("state", state)
                        .claim("response_uri", authorizationRequest.getResponseUri());
            }

            if (verifierDid != null && verifierDid.startsWith(Constants.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER)) {
                claimsBuilder.claim(
                        "client_metadata",
                        new ClientMetadataDto(VP_FORMATS_SUPPORTED)
                );
            }

            // DCQL-only: never emit presentation_definition / presentation_definition_uri claims (spec).
            if (authorizationRequest.getDcqlQuery() != null) {
                String dcqlQueryJson = objectMapper.writeValueAsString(authorizationRequest.getDcqlQuery());
                claimsBuilder.claim("dcql_query", JSONObjectUtils.parse(dcqlQueryJson));
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            if ("x5c".equalsIgnoreCase(signatureKeyReferenceType)) {
                X5cSigningMaterial material = loadX5cSigningMaterial();
                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("oauth-authz-req+jwt"))
                        .x509CertChain(material.certChain())
                        .build();
                SignedJWT signedJWT = new SignedJWT(header, claimsSet);
                signedJWT.sign(new ECDSASigner((ECPrivateKey) material.privateKey()));
                return signedJWT.serialize();
            }

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"))
                    .keyID(verifyPublicKeyURI)
                    .build();
            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
            JWSSigner signer = new Ed25519Signer(keyManagementService.getKeyPair());

            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException | JsonProcessingException e) {
            log.error("Error generating authorization request JWT", e);
            throw new JWTCreationException(e);
        }
    }

    private record X5cSigningMaterial(PrivateKey privateKey, List<Base64> certChain) {}

    private X5cSigningMaterial loadX5cSigningMaterial() {
        try {
            Resource resource = resourceLoader.getResource(x5cKeystorePath);
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            try (InputStream inputStream = resource.getInputStream()) {
                keystore.load(inputStream, x5cKeystorePassword.toCharArray());
            }

            String alias = null;
            for (Enumeration<String> aliases = keystore.aliases(); aliases.hasMoreElements();) {
                String candidate = aliases.nextElement();
                if (!keystore.isKeyEntry(candidate)) {
                    continue;
                }
                X509Certificate cert = (X509Certificate) keystore.getCertificate(candidate);
                if (cert == null || !"EC".equals(cert.getPublicKey().getAlgorithm())) {
                    continue;
                }
                if (cert.getPublicKey() instanceof ECPublicKey ecPublicKey
                        && ecPublicKey.getParams().getCurve().getField().getFieldSize() == 256) {
                    alias = candidate;
                    break;
                }
            }
            if (alias == null) {
                throw new JWTCreationException();
            }

            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, x5cKeystorePassword.toCharArray());
            if (privateKey == null) {
                throw new JWTCreationException();
            }

            Certificate[] chain = keystore.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                X509Certificate leaf = (X509Certificate) keystore.getCertificate(alias);
                if (leaf == null) {
                    throw new JWTCreationException();
                }
                chain = new Certificate[]{leaf};
            }

            List<Base64> certChain = new ArrayList<>(chain.length);
            for (Certificate certificate : chain) {
                certChain.add(Base64.encode(((X509Certificate) certificate).getEncoded()));
            }
            return new X5cSigningMaterial(privateKey, certChain);
        } catch (JWTCreationException e) {
            throw e;
        } catch (Exception e) {
            throw new JWTCreationException();
        }
    }
}
