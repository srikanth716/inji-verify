package io.inji.verify.validation;

import io.inji.verify.dto.authorizationrequest.VPRequestCreateDto;
import io.inji.verify.enums.ErrorCode;

public final class VPRequestCreateValidator {

    private VPRequestCreateValidator() {
    }

    public static ErrorCode validate(VPRequestCreateDto request) {
        if (request == null) {
            return ErrorCode.INVALID_REQUEST_FORMAT;
        }
        if (request.getClientId() == null || request.getClientId().isBlank()) {
            return ErrorCode.CLIENT_ID_REQUIRED;
        }
        return DcqlQueryValidator.validate(request.getDcqlQuery());
    }
}
