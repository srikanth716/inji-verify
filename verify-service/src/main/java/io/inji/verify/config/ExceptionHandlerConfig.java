package io.inji.verify.config;

import io.inji.verify.dto.core.ErrorDto;
import io.inji.verify.exception.CredentialStatusCheckException;
import io.inji.verify.exception.VPRequestValidationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import static io.inji.verify.utils.Utils.getResponseEntityForCredentialStatusException;

@ControllerAdvice
public class ExceptionHandlerConfig {

    @ExceptionHandler(CredentialStatusCheckException.class)
    public ResponseEntity<Object> handle(CredentialStatusCheckException ex) {
        return getResponseEntityForCredentialStatusException(ex);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDto> handle(MethodArgumentNotValidException ex) {
        VPRequestValidationException mapped = VPRequestValidationException.from(ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorDto(mapped.getErrorCode()));
    }
}
