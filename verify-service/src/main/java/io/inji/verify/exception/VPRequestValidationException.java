package io.inji.verify.exception;

import io.inji.verify.enums.ErrorCode;
import lombok.Getter;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

@Getter
public class VPRequestValidationException extends RuntimeException {

    private final ErrorCode errorCode;

    public VPRequestValidationException(ErrorCode errorCode) {
        super(errorCode.getErrorMessage());
        this.errorCode = errorCode;
    }

    public static VPRequestValidationException from(MethodArgumentNotValidException ex) {
        ErrorCode errorCode = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(VPRequestValidationException::toErrorCode)
                .orElse(ErrorCode.INVALID_REQUEST_FORMAT);
        return new VPRequestValidationException(errorCode);
    }

    private static ErrorCode toErrorCode(FieldError fieldError) {
        if ("clientId".equals(fieldError.getField())) {
            return ErrorCode.CLIENT_ID_REQUIRED;
        }
        String message = fieldError.getDefaultMessage();
        if (message == null || message.isBlank()) {
            return ErrorCode.INVALID_REQUEST_FORMAT;
        }
        try {
            return ErrorCode.valueOf(message);
        } catch (IllegalArgumentException ignored) {
            return ErrorCode.INVALID_REQUEST_FORMAT;
        }
    }
}
