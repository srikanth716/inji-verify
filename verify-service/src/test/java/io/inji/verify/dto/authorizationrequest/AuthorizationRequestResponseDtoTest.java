package io.inji.verify.dto.authorizationrequest;

import static org.junit.jupiter.api.Assertions.*;

import io.inji.verify.shared.Constants;
import org.junit.jupiter.api.Test;

import java.time.Instant;

public class AuthorizationRequestResponseDtoTest {

    @Test
    public void ShouldTestConstructorSetsFieldsCorrectly() {
        String clientId = "testClientId";
        String dcqlQuery = "{\"credentials\":[]}";
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
