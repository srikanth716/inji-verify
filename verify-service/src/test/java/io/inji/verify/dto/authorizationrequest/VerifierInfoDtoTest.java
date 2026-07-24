package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VerifierInfoDtoTest {

    private static final ObjectMapper MAPPER =
            Jackson2ObjectMapperBuilder.json().modules(new ParameterNamesModule()).build();

    @Test
    void hasContent_returnsFalseWhenAllFieldsAreAbsent() {
        assertFalse(new VerifierInfoDto().hasContent());
        assertFalse(new VerifierInfoDto(null, null, null).hasContent());
        assertFalse(new VerifierInfoDto("", "  ", List.of()).hasContent());
    }

    @Test
    void hasContent_returnsTrueForPartialFields() {
        assertTrue(new VerifierInfoDto("Example Bank", null, null).hasContent());
        assertTrue(new VerifierInfoDto(null, "https://verifier.example/privacy", null).hasContent());
        assertTrue(new VerifierInfoDto(null, null, List.of(new AttestationDto("registration_certificate", null, null))).hasContent());
    }

    @Test
    void serialization_usesSnakeCasePropertyNamesAndOmitsNulls() throws Exception {
        VerifierInfoDto full = new VerifierInfoDto(
                "Example Bank",
                "https://verifier.example/privacy",
                List.of(new AttestationDto(
                        "registration_certificate",
                        "https://regulator.example",
                        "eyJ...")));
        JsonNode out = MAPPER.valueToTree(full);
        assertEquals("Example Bank", out.get("organization_name").asText());
        assertEquals("https://verifier.example/privacy", out.get("policy_uri").asText());
        assertEquals("registration_certificate", out.get("attestations").get(0).get("type").asText());
        assertEquals("https://regulator.example", out.get("attestations").get(0).get("issuer").asText());

        JsonNode partial = MAPPER.valueToTree(new VerifierInfoDto("Example Bank", null, null));
        assertTrue(partial.has("organization_name"));
        assertFalse(partial.has("policy_uri"));
        assertFalse(partial.has("attestations"));
    }
}
