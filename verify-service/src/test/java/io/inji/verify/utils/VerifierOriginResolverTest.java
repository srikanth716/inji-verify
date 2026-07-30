package io.inji.verify.utils;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VerifierOriginResolverTest {

    @Test
    void resolvesOriginHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void fallsBackToReferer() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "https://verify.example.com/path?q=1");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void hintMustMatchSingleOrigin() {
        assertTrue(VerifierOriginResolver.hintMatchesVerifierOrigin(
                List.of("https://verify.example.com"), "https://verify.example.com"));
        assertFalse(VerifierOriginResolver.hintMatchesVerifierOrigin(
                List.of("https://evil.example.com"), "https://verify.example.com"));
        assertTrue(VerifierOriginResolver.hintMatchesVerifierOrigin(null, "https://verify.example.com"));
    }
}
