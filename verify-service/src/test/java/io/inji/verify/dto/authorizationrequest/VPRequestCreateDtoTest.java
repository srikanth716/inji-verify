package io.inji.verify.dto.authorizationrequest;

import io.inji.verify.dto.dcql.CredentialMetaDto;
import io.inji.verify.dto.dcql.CredentialQueryDto;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.testsupport.DcqlTestFixtures;
import io.inji.verify.validation.DcqlQueryValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class VPRequestCreateDtoTest {

    @Test
    public void testConstructor() {
        String clientId = "client123";
        String transactionId = "tx123";
        String nonce = "nonce123";
        DCQLQueryDto dcqlQuery = DcqlTestFixtures.minimalDcqlDto();

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
    void dcqlQueryDto_WithMissingMeta_IsInvalid() {
        DCQLQueryDto dcqlQuery = new DCQLQueryDto(
                List.of(new CredentialQueryDto("cred1", "dc+sd-jwt", null, null, null)),
                null);

        assertEquals(ErrorCode.DCQL_META_REQUIRED, DcqlQueryValidator.validate(dcqlQuery));
    }

    @Test
    void dcqlQueryDto_WithEmptyMeta_IsValid() {
        DCQLQueryDto dcqlQuery = new DCQLQueryDto(
                List.of(new CredentialQueryDto(
                        "cred1", "dc+sd-jwt", new CredentialMetaDto(null, null), null, null)),
                null);

        assertNull(DcqlQueryValidator.validate(dcqlQuery));
    }
}
