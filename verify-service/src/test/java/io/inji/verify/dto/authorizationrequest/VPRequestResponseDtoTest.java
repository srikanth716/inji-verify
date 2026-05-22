package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class VPRequestResponseDtoTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testConstructor() throws Exception {
        String transactionId = "tx123";
        String requestId = "req123";
        AuthorizationRequestResponseDto authorizationDetails =
                new AuthorizationRequestResponseDto("client123", objectMapper.readTree("{\"credentials\":[]}"),
                        "nonce123", "url", false, false);
        long expiresAt = 1687318740000L;

        VPRequestResponseDto vpRequestResponseDto = new VPRequestResponseDto(transactionId, requestId, authorizationDetails, expiresAt ,"url");

        assertEquals(transactionId, vpRequestResponseDto.getTransactionId());
        assertEquals(requestId, vpRequestResponseDto.getRequestId());
        assertEquals(authorizationDetails, vpRequestResponseDto.getAuthorizationDetails());
        assertEquals(expiresAt, vpRequestResponseDto.getExpiresAt());
        assertEquals("url", vpRequestResponseDto.authorizationDetails.getResponseUri());
    }
}
