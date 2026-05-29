package io.inji.verify.validation;

import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.testsupport.DcqlTestFixtures;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class VPRequestCreateValidatorTest {

    @Test
    void validate_WhenRequestIsNull_ReturnsInvalidRequestFormat() {
        assertEquals(ErrorCode.INVALID_REQUEST_FORMAT, VPRequestCreateValidator.validate(null));
    }

    @Test
    void validate_WhenClientIdMissing_ReturnsClientIdRequired() {
        VPRequestCreateDto dto = new VPRequestCreateDto(
                null, "tx", "nonce", DcqlTestFixtures.minimalDcqlDto(), false, false);

        assertEquals(ErrorCode.CLIENT_ID_REQUIRED, VPRequestCreateValidator.validate(dto));
    }

    @Test
    void validate_WhenDcqlQueryMissing_ReturnsDcqlQueryRequired() {
        VPRequestCreateDto dto = new VPRequestCreateDto(
                "client", "tx", "nonce", null, false, false);

        assertEquals(ErrorCode.DCQL_QUERY_REQUIRED, VPRequestCreateValidator.validate(dto));
    }

    @Test
    void validate_WhenValid_ReturnsNull() {
        VPRequestCreateDto dto = new VPRequestCreateDto(
                "client", "tx", "nonce", DcqlTestFixtures.minimalDcqlDto(), false, false);

        assertNull(VPRequestCreateValidator.validate(dto));
    }
}
