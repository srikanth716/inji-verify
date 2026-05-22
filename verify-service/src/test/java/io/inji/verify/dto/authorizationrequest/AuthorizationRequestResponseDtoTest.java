package io.inji.verify.dto.authorizationrequest;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.shared.Constants;
import org.junit.jupiter.api.Test;

import java.time.Instant;

public class AuthorizationRequestResponseDtoTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void ShouldTestConstructorSetsFieldsCorrectly() throws Exception {
        String clientId = "testClientId";
        var dcqlQuery = objectMapper.readTree("{\"credentials\":[]}");
        String nonce = "testNonce";
        String responseUri = "testUri";

        AuthorizationRequestResponseDto responseDto =
                new AuthorizationRequestResponseDto(clientId, dcqlQuery, nonce, responseUri, true, false);

        assertEquals(Constants.RESPONSE_TYPE, responseDto.getResponseType());
        assertEquals(clientId, responseDto.getClientId());
        assertEquals(dcqlQuery, responseDto.getDcqlQuery());
        assertEquals(responseUri, responseDto.getResponseUri());
        assertEquals(nonce, responseDto.getNonce());
        assertTrue(Instant.now().toEpochMilli() >= responseDto.getIssuedAt());
        assertTrue(responseDto.isAcceptVPWithoutHolderProof());
    }
}
