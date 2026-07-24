package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Attestation payload included in {@link VerifierInfoDto}.
 * Fields are carried through as opaque data — no credential validation is applied.
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AttestationDto {
    private String type;
    private String issuer;
    private String credential;
}
