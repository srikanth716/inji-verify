package io.inji.verify.config;

import io.inji.verify.dto.core.ErrorDto;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.exception.CredentialStatusCheckException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Arrays;
import java.util.Optional;

import static io.inji.verify.utils.Utils.getResponseEntityForCredentialStatusException;

@ControllerAdvice
public class ExceptionHandlerConfig {

    @ExceptionHandler(CredentialStatusCheckException.class)
    public ResponseEntity<Object> handle(CredentialStatusCheckException ex) {
        return getResponseEntityForCredentialStatusException(ex);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDto> handleMethodArgumentNotValid(MethodArgumentNotValidException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorDto(resolveValidationError(ex)));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorDto> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorDto(ErrorCode.INVALID_REQUEST_FORMAT));
    }

    private ErrorCode resolveValidationError(MethodArgumentNotValidException ex) {
        Optional<ErrorCode> fieldError = ex.getBindingResult().getFieldErrors().stream()
                .map(this::mapFieldError)
                .flatMap(Optional::stream)
                .findFirst();
        if (fieldError.isPresent()) {
            return fieldError.get();
        }

        return ex.getBindingResult().getGlobalErrors().stream()
                .map(this::mapObjectError)
                .flatMap(Optional::stream)
                .findFirst()
                .orElse(ErrorCode.INVALID_REQUEST_FORMAT);
    }

    private Optional<ErrorCode> mapFieldError(FieldError fieldError) {
        if ("clientId".equals(fieldError.getField())) {
            return Optional.of(ErrorCode.CLIENT_ID_REQUIRED);
        }
        if ("dcqlQuery".equals(fieldError.getField())) {
            return Optional.of(ErrorCode.DCQL_QUERY_REQUIRED);
        }
        return mapErrorCodeFromMessage(fieldError.getDefaultMessage());
    }

    private Optional<ErrorCode> mapObjectError(ObjectError objectError) {
        return mapErrorCodeFromMessage(objectError.getDefaultMessage());
    }

    private Optional<ErrorCode> mapErrorCodeFromMessage(String message) {
        if (message == null || message.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(ErrorCode.valueOf(message));
        } catch (IllegalArgumentException ignored) {
            return Arrays.stream(ErrorCode.values())
                    .filter(errorCode -> errorCode.getErrorCode().equals(message))
                    .findFirst();
        }
    }
}
