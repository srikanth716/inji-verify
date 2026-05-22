package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class VPRequestCreateDtoTest {
    @Test
    public void testConstructor() throws Exception {
        String clientId = "client123";
        String transactionId = "tx123";
        String nonce = "nonce123";
        ObjectMapper objectMapper = new ObjectMapper();
        var dcqlQuery = objectMapper.readTree("{\"credentials\":[]}");

        VPRequestCreateDto vpRequestCreateDto =
                new VPRequestCreateDto(clientId, transactionId, nonce, dcqlQuery, false, false);

        assertEquals(clientId, vpRequestCreateDto.getClientId());
        assertEquals(transactionId, vpRequestCreateDto.getTransactionId());
        assertEquals(nonce, vpRequestCreateDto.getNonce());
        assertEquals(dcqlQuery, vpRequestCreateDto.getDcqlQuery());
        assertFalse(vpRequestCreateDto.isAcceptVPWithoutHolderProof());
    }
}
