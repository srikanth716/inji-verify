package io.inji.verify.controller;

import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.http.converter.HttpMessageNotReadableException;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.dto.authorizationrequest.VPRequestResponseDto;
import io.inji.verify.dto.authorizationrequest.VPRequestStatusDto;
import io.inji.verify.dto.core.ErrorDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.exception.VPRequestNotFoundException;
import io.inji.verify.exception.VPRequestValidationException;
import io.inji.verify.services.VerifiablePresentationRequestService;
import io.inji.verify.validator.DcqlValidator;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import static io.inji.verify.shared.Constants.COOKIE_NAME;
import static io.inji.verify.shared.Constants.VP_REQUEST_URI;

@RestController
@Slf4j
@CrossOrigin(originPatterns = "*", allowedHeaders = "Content-Type", allowCredentials = "true")
public class VPRequestController {

    @Value("${inji.verify.cookie-duration-in-minute:#{5}}")
    int cookieDurationInMinute;

    @Value("${inji.verify.cookie-secure-value:#{true}}")
    boolean cookieIsSecure;

    @Value("${inji.verify.cookie-path}")
    String cookiePath;

    @Value("${inji.verify.cookie-same-site}")
    String cookieSameSite;

    final VerifiablePresentationRequestService verifiablePresentationRequestService;
    final DcqlValidator dcqlValidator;

    public VPRequestController(VerifiablePresentationRequestService verifiablePresentationRequestService, DcqlValidator dcqlValidator) {
        this.verifiablePresentationRequestService = verifiablePresentationRequestService;
        this.dcqlValidator = dcqlValidator;
    }

    @PostMapping(path = VP_REQUEST_URI, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createVPRequest(@Valid @RequestBody VPRequestCreateDto vpRequestCreate) {
        dcqlValidator.validate(vpRequestCreate.getDcqlQuery());
        return processCreateVPRequest(vpRequestCreate, false);
    }

    @PostMapping(path = "/v2/vp-session-request", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createVPSessionRequest(@Valid @RequestBody VPRequestCreateDto vpRequestCreate) {
        dcqlValidator.validate(vpRequestCreate.getDcqlQuery());
        return processCreateVPRequest(vpRequestCreate, true);
    }

    @ExceptionHandler(VPRequestValidationException.class)
    public ResponseEntity<ErrorDto> handleVPRequestValidationException(VPRequestValidationException e) {
        log.error("VP request validation error: {}", e.getMessage());
        ErrorCode errorCode = e.getErrorCode();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorDto(errorCode));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorDto> handleUnreadable(HttpMessageNotReadableException ex) {
        log.error("VP request body unreadable: {}", ex.getMessage());
        return handleVPRequestValidationException(
                new VPRequestValidationException(
                        ErrorCode.INVALID_REQUEST_FORMAT));
    }

    @NotNull
    private ResponseEntity<Object> processCreateVPRequest(VPRequestCreateDto vpRequestCreate, boolean createCookie) {
        VPRequestResponseDto authorizationRequestResponse = verifiablePresentationRequestService.createAuthorizationRequest(vpRequestCreate);

            if (createCookie) {
                String transactionId = authorizationRequestResponse.getTransactionId();
                String cookieValue = Base64.getEncoder().encodeToString(transactionId.getBytes(StandardCharsets.UTF_8));
                ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, cookieValue)
                        .httpOnly(true)
                        .secure(cookieIsSecure)
                        .path(cookiePath)
                        .sameSite(cookieSameSite)
                        .maxAge(Duration.ofMinutes(cookieDurationInMinute))
                        .build();
                return ResponseEntity.status(HttpStatus.CREATED)
                        .header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(authorizationRequestResponse);
            }

        return ResponseEntity.status(HttpStatus.CREATED).body(authorizationRequestResponse);
    }

    @GetMapping(path = "/vp-request/{requestId}/status")
    public DeferredResult<VPRequestStatusDto> getStatus(@PathVariable String requestId) {
        return verifiablePresentationRequestService.getStatus(requestId);
    }

    @GetMapping(path = "/v2/vp-request/{requestId}" , produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<Object> getVPRequest(@PathVariable String requestId) {
        try {
            return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationRequestService.getVPRequestJwt(requestId));
        } catch (VPRequestNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorDto(ErrorCode.NO_AUTH_REQUEST));
        }
    }
}