package io.inji.verify.utils;

import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.shared.Constants;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class OriginAudienceResolverTest {

    @Test
    void toOriginAudience_prefixesOriginWithoutTrailingSlash() {
        assertEquals("origin:https://verify.example.com",
                OriginAudienceResolver.toOriginAudience("https://verify.example.com"));
    }

    @Test
    void canonicalize_stripsPathAndNormalizes() {
        assertEquals("https://verify.example.com",
                OriginAudienceResolver.canonicalize("https://verify.example.com/path?q=1").orElseThrow());
        assertEquals("https://verify.example.com:8443",
                OriginAudienceResolver.canonicalize("https://verify.example.com:8443/").orElseThrow());
        assertTrue(OriginAudienceResolver.canonicalize("ftp://verify.example.com").isEmpty());
        assertTrue(OriginAudienceResolver.canonicalize(null).isEmpty());
    }

    @Test
    void audienceMatches_acceptsLegacyTrailingSlash() {
        assertTrue(OriginAudienceResolver.audienceMatches(
                "origin:https://verify.example.com",
                "origin:https://verify.example.com/"));
        assertTrue(OriginAudienceResolver.audienceMatches(
                "origin:https://verify.example.com/",
                "origin:https://verify.example.com"));
        assertFalse(OriginAudienceResolver.audienceMatches(
                "origin:https://verify.example.com",
                "origin:https://other.example.com"));
    }

    @Test
    void directPost_returnsClientId() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "decentralized_identifier:did:web:verify.example.com",
                null, null, "nonce-value-123456", "https://verify.example.com/cb",
                false, false, Constants.RESPONSE_MODE_DIRECT_POST, null);

        OriginAudienceResolver.ResolveResult result = OriginAudienceResolver.resolve(auth, Optional.empty());

        assertTrue(result.isOk());
        assertEquals("decentralized_identifier:did:web:verify.example.com", result.expectedAudience());
    }

    @Test
    void dcApi_returnsOriginAudience_whenOriginInExpectedOrigins() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "decentralized_identifier:did:web:verify.example.com",
                null, null, "nonce-value-123456", null,
                false, false, Constants.RESPONSE_MODE_DC_API,
                List.of("https://verify.example.com"));

        OriginAudienceResolver.ResolveResult result =
                OriginAudienceResolver.resolve(auth, Optional.of("https://verify.example.com"));

        assertTrue(result.isOk());
        assertEquals("origin:https://verify.example.com", result.expectedAudience());
    }

    @Test
    void dcApi_fails_whenOriginMissing() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "decentralized_identifier:did:web:verify.example.com",
                null, null, "nonce-value-123456", null,
                false, false, Constants.RESPONSE_MODE_DC_API,
                List.of("https://verify.example.com"));

        OriginAudienceResolver.ResolveResult result = OriginAudienceResolver.resolve(auth, Optional.empty());

        assertFalse(result.isOk());
        assertEquals(ErrorCode.VERIFIER_ORIGIN_REQUIRED, result.error());
    }

    @Test
    void dcApi_fails_whenOriginNotAllowed() {
        AuthorizationRequestResponseDto auth = new AuthorizationRequestResponseDto(
                "decentralized_identifier:did:web:verify.example.com",
                null, null, "nonce-value-123456", null,
                false, false, Constants.RESPONSE_MODE_DC_API,
                List.of("https://verify.example.com"));

        OriginAudienceResolver.ResolveResult result =
                OriginAudienceResolver.resolve(auth, Optional.of("https://evil.example.com"));

        assertFalse(result.isOk());
        assertEquals(ErrorCode.SUBMISSION_ORIGIN_NOT_ALLOWED, result.error());
    }
}
