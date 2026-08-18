package io.inji.verify.utils;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

class VerifierOriginResolverTest {

    @Test
    void should_resolveOrigin_when_originHeaderIsPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void should_resolveOrigin_when_onlyRefererIsPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "https://verify.example.com/path?q=1");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void should_preferOrigin_when_bothOriginAndRefererPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Origin", "https://verify.example.com");
        request.addHeader("Referer", "https://other.example.com/path");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }

    @Test
    void should_returnEmpty_when_originAndRefererMissing() {
        assertTrue(VerifierOriginResolver.resolve(new MockHttpServletRequest()).isEmpty());
        assertTrue(VerifierOriginResolver.resolve(null).isEmpty());
    }

    @Test
    void should_returnEmpty_when_refererIsNotHttpOrigin() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "ftp://verify.example.com/path");
        assertTrue(VerifierOriginResolver.resolve(request).isEmpty());
    }

    @Test
    void should_canonicalizeReferer_when_pathAndQueryPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Referer", "https://Verify.Example.COM:443/path?q=1#frag");
        assertEquals("https://verify.example.com", VerifierOriginResolver.resolve(request).orElseThrow());
    }
}
