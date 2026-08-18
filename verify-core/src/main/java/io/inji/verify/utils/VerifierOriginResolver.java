package io.inji.verify.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * Determines the verifier web origin from the HTTP request (Option A for DC API expected_origins).
 * <p>
 * Prefers the {@code Origin} header (always sent by browsers on CORS and same-origin POST).
 * Falls back to the origin of {@code Referer} only when Origin is absent. Modern Referrer-Policy
 * defaults and privacy extensions often strip or downgrade Referer, so that path rarely helps;
 * if both are missing the call fails closed with {@code VERIFIER_ORIGIN_REQUIRED}.
 */
public final class VerifierOriginResolver {

    private VerifierOriginResolver() {
    }

    /**
     * Prefer the {@code Origin} header; fall back to the origin of {@code Referer}.
     * Returns empty if neither yields a usable http(s) origin.
     * <p>
     * Both headers are passed through {@link #canonicalize(String)}, which parses the URI,
     * discards path/query, validates the scheme, and handles {@link URISyntaxException}.
     */
    public static Optional<String> resolve(HttpServletRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        String originHeader = request.getHeader("Origin");
        if (StringUtils.hasText(originHeader) && !"null".equalsIgnoreCase(originHeader.trim())) {
            return canonicalize(originHeader.trim());
        }
        String referer = request.getHeader("Referer");
        if (StringUtils.hasText(referer)) {
            return canonicalize(referer.trim());
        }
        return Optional.empty();
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

    private static String stripTrailingSlash(String value) {
        if (value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }
}
