package io.inji.verify.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

/**
 * Determines the verifier web origin from the HTTP request (Option A for DC API expected_origins).
 */
public final class VerifierOriginResolver {

    private VerifierOriginResolver() {
    }

    /**
     * Prefer the {@code Origin} header; fall back to the origin of {@code Referer}.
     * Returns empty if neither yields a usable http(s) origin.
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
            try {
                URI uri = new URI(referer.trim());
                if (uri.getScheme() == null || uri.getHost() == null) {
                    return Optional.empty();
                }
                StringBuilder origin = new StringBuilder();
                origin.append(uri.getScheme()).append("://").append(uri.getHost());
                if (uri.getPort() > 0) {
                    origin.append(":").append(uri.getPort());
                }
                return canonicalize(origin.toString());
            } catch (URISyntaxException e) {
                return Optional.empty();
            }
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

    public static boolean hintMatchesVerifierOrigin(List<String> expectedOriginsHint, String verifierOrigin) {
        if (expectedOriginsHint == null || expectedOriginsHint.isEmpty()) {
            return true;
        }
        if (expectedOriginsHint.size() != 1) {
            return false;
        }
        return canonicalize(expectedOriginsHint.get(0))
                .map(hint -> hint.equals(verifierOrigin))
                .orElse(false);
    }

    private static String stripTrailingSlash(String value) {
        if (value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }
}
