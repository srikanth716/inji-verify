package io.inji.verify.utils;

import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.shared.Constants;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;

/**
 * Resolves the expected audience string for VP holder-binding checks.
 * For {@code dc_api}, returns {@code origin:<canonical-origin>} (no trailing slash);
 * otherwise {@code client_id}.
 */
public final class OriginAudienceResolver {

    private OriginAudienceResolver() {
    }

    public record ResolveResult(String expectedAudience, ErrorCode error) {
        public static ResolveResult ok(String expectedAudience) {
            return new ResolveResult(expectedAudience, null);
        }

        public static ResolveResult fail(ErrorCode error) {
            return new ResolveResult(null, error);
        }

        public boolean isOk() {
            return error == null && StringUtils.hasText(expectedAudience);
        }
    }

    /**
     * Builds the OpenID4VP origin-bound audience ({@code origin:https://host[:port]}).
     * {@code canonicalOrigin} must be slash-free ({@code scheme://host[:port]}).
     * OpenID4VP 1.0 (post PR #727) and cmwallet use no trailing slash after the origin.
     */
    public static String toOriginAudience(String canonicalOrigin) {
        return "origin:" + canonicalOrigin;
    }

    /**
     * For {@code response_mode=dc_api}: require submission Origin ∈ persisted {@code expected_origins},
     * then return {@code origin:<Origin>}. Otherwise return the auth request {@code client_id}.
     */
    public static ResolveResult resolve(AuthorizationRequestResponseDto authRequest, HttpServletRequest request) {
        if (authRequest == null) {
            return ResolveResult.fail(ErrorCode.NO_MATCHING_VP_REQUEST);
        }
        if (!Constants.RESPONSE_MODE_DC_API.equals(authRequest.getResponseMode())) {
            String clientId = authRequest.getClientId();
            if (!StringUtils.hasText(clientId)) {
                return ResolveResult.fail(ErrorCode.CLIENT_ID_VALIDATION_FAILED);
            }
            return ResolveResult.ok(clientId);
        }

        Optional<String> submissionOrigin = VerifierOriginResolver.resolve(request);
        if (submissionOrigin.isEmpty()) {
            return ResolveResult.fail(ErrorCode.VERIFIER_ORIGIN_REQUIRED);
        }

        String origin = submissionOrigin.get();
        if (!isOriginAllowed(authRequest.getExpectedOrigins(), origin)) {
            return ResolveResult.fail(ErrorCode.SUBMISSION_ORIGIN_NOT_ALLOWED);
        }
        return ResolveResult.ok(toOriginAudience(origin));
    }

    /**
     * True if {@code actual} matches the expected DC API / direct_post audience.
     * For origin-bound audiences, also accept a legacy trailing-slash form from older wallets/specs.
     */
    public static boolean audienceMatches(String expectedAudience, String actual) {
        if (!StringUtils.hasText(expectedAudience) || !StringUtils.hasText(actual)) {
            return false;
        }
        if (expectedAudience.equals(actual)) {
            return true;
        }
        if (expectedAudience.startsWith("origin:") && actual.startsWith("origin:")) {
            String expectedNorm = stripOriginAudienceTrailingSlash(expectedAudience);
            String actualNorm = stripOriginAudienceTrailingSlash(actual);
            return expectedNorm.equals(actualNorm);
        }
        return false;
    }

    private static String stripOriginAudienceTrailingSlash(String originAudience) {
        // origin:https://host/ → origin:https://host (only a single trailing slash after the origin)
        if (originAudience.endsWith("/") && originAudience.length() > "origin:".length() + 1) {
            return originAudience.substring(0, originAudience.length() - 1);
        }
        return originAudience;
    }

    private static boolean isOriginAllowed(List<String> expectedOrigins, String canonicalSubmissionOrigin) {
        if (expectedOrigins == null || expectedOrigins.isEmpty()) {
            return false;
        }
        for (String expected : expectedOrigins) {
            Optional<String> canonicalExpected = VerifierOriginResolver.canonicalize(expected);
            if (canonicalExpected.isPresent() && canonicalExpected.get().equals(canonicalSubmissionOrigin)) {
                return true;
            }
        }
        return false;
    }
}
