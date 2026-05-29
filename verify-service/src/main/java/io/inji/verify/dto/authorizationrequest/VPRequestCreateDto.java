package io.inji.verify.dto.authorizationrequest;

import io.inji.verify.dto.dcql.DCQLQueryDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
@NotNull
public class VPRequestCreateDto {

    @NotNull(message = "Client Id must not be null")
    @NotBlank(message = "Client Id must not be empty")
    String clientId;
    String transactionId;
    String nonce;
    @Valid
    @NotNull(message = "DCQL query must not be null")
    private DCQLQueryDto dcqlQuery;
    boolean acceptVPWithoutHolderProof;
    boolean responseCodeValidationRequired;
}
