package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.enums.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class VPRequestCreateDtoTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testConstructor() throws Exception {
        String clientId = "client123";
        String transactionId = "tx123";
        String nonce = "nonce123";
        JsonNode dcqlQuery = MAPPER.readTree(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"cred1\"]}}]}");

        VPRequestCreateDto vpRequestCreateDto =
                new VPRequestCreateDto(clientId, transactionId, nonce, dcqlQuery, true, false);

        assertEquals(clientId, vpRequestCreateDto.getClientId());
        assertEquals(transactionId, vpRequestCreateDto.getTransactionId());
        assertEquals(nonce, vpRequestCreateDto.getNonce());
        assertEquals(dcqlQuery, vpRequestCreateDto.getDcqlQuery());
        assertEquals(true, vpRequestCreateDto.isAcceptVPWithoutHolderProof());
        assertEquals(false, vpRequestCreateDto.isResponseCodeValidationRequired());
    }

    @Test
    void validateDcqlQuery_WhenMetaMissing_ReturnsMetaRequired() throws Exception {
        JsonNode dcqlQuery = MAPPER.readTree(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\"}]}");
        VPRequestCreateDto dto =
                new VPRequestCreateDto("client", "tx", "nonce", dcqlQuery, false, false);

        assertEquals(ErrorCode.DCQL_META_REQUIRED, dto.validateDcqlQuery());
    }

    @Test
    void validateDcqlQuery_WhenMetaEmptyObject_IsValid() throws Exception {
        JsonNode dcqlQuery = MAPPER.readTree(
                "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"dc+sd-jwt\",\"meta\":{}}]}");
        VPRequestCreateDto dto =
                new VPRequestCreateDto("client", "tx", "nonce", dcqlQuery, false, false);

        assertNull(dto.validateDcqlQuery());
    }
}
