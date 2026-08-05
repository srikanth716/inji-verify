package io.inji.verify.utils;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

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
    void prefersOriginOverReferer() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");
        request.addHeader("Referer", "https://other.example.com/path");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void emptyWhenOriginAndRefererMissing() {
        assertTrue(VerifierOriginResolver.resolve(new MockHttpServletRequest()).isEmpty());
        assertTrue(VerifierOriginResolver.resolve(null).isEmpty());
    }
}
