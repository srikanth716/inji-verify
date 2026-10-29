package io.inji.verify.dto.dcql;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialMetaDtoTest {

    /** Same mapper shape as verify-service: parameter names and fail on unknown properties. */
    private static final ObjectMapper MAPPER = Jackson2ObjectMapperBuilder.json()
            .modules(new ParameterNamesModule())
            .featuresToEnable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    @Test
    void acceptsDoctypeValueOnVpSessionRequest() throws Exception {
        String json = """
                {"clientId":"decentralized_identifier:did:web:injiverify.dev-int-inji.mosip.net:v1:verify","nonce":"6VfG6E3u3RzMALW6y6UN9kkqta_eTh7yj2EVX_r0arI","dcqlQuery":{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"id":"family_name","path":["org.iso.18013.5.1","family_name"]},{"id":"given_name","path":["org.iso.18013.5.1","given_name"]},{"id":"birth_date","path":["org.iso.18013.5.1","birth_date"]},{"id":"document_number","path":["org.iso.18013.5.1","document_number"]}]}]},"responseMode":"direct_post"}
                """;

        VPRequestCreateDto request = MAPPER.readValue(json, VPRequestCreateDto.class);

        assertEquals("org.iso.18013.5.1.mDL",
                request.getDcqlQuery().getCredentials().getFirst().getMeta().getDoctypeValue());
    }
}
