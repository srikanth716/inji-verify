package io.inji.verify.utils;

import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.shared.Constants;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

/**
 * Resolves the expected audience string for VP holder-binding checks and canonicalizes
 * verifier / submission origins for DC API {@code expected_origins}.
 * <p>
 * For {@code dc_api}, returns {@code origin:<canonical-origin>} (no trailing slash);
 * otherwise {@code client_id}. Origin / Referer extraction stays in the web layer; this
 * class only receives an optional raw origin string.
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
     */
    public static String toOriginAudience(String canonicalOrigin) {
        return "origin:" + canonicalOrigin;
    }

    /**
     * Normalize to scheme://host[:port] with no path, query, or trailing slash.
     */
    public static Optional<String> canonicalize(String raw) {
        if (!StringUtils.hasText(raw)) {
            return Optional.empty();
        }
        try {
            URI uri = new URI(raw.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                // Origin header is typically already "https://host" without path
                if (raw.matches("^https?://[^/]+$")) {
                    return Optional.of(stripTrailingSlash(raw.trim()));
                }
                return Optional.empty();
            }
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return Optional.empty();
            }
            StringBuilder origin = new StringBuilder();
            origin.append(scheme.toLowerCase()).append("://").append(host.toLowerCase());
            int port = uri.getPort();
            if (port > 0
                    && !(("https".equalsIgnoreCase(scheme) && port == 443)
                    || ("http".equalsIgnoreCase(scheme) && port == 80))) {
                origin.append(":").append(port);
            }
            return Optional.of(origin.toString());
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    /**
     * For {@code response_mode=dc_api}: require submission Origin ∈ persisted {@code expected_origins},
     * then return {@code origin:<Origin>}. Otherwise return the auth request {@code client_id}.
     *
     * @param submissionOrigin raw Origin or Referer from the web layer (may be empty)
     */
    public static ResolveResult resolve(AuthorizationRequestResponseDto authRequest, Optional<String> submissionOrigin) {
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

        Optional<String> canonicalSubmission = canonicalize(submissionOrigin.orElse(null));
        if (canonicalSubmission.isEmpty()) {
            return ResolveResult.fail(ErrorCode.VERIFIER_ORIGIN_REQUIRED);
        }

        String origin = canonicalSubmission.get();
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
            Optional<String> canonicalExpected = canonicalize(expected);
            if (canonicalExpected.isPresent() && canonicalExpected.get().equals(canonicalSubmissionOrigin)) {
                return true;
            }
        }
        return false;
    }

    private static String stripTrailingSlash(String value) {
        if (value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }
}
