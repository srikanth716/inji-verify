package io.inji.verify.dto.authorizationrequest;

import io.inji.verify.dto.dcql.DCQLQueryDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class VPRequestCreateDto {

    String clientId;
    String transactionId;
    String nonce;
    @Valid
    @NotNull(message = "DCQL query must not be null")
    private DCQLQueryDto dcqlQuery;
    boolean acceptVPWithoutHolderProof;
    boolean responseCodeValidationRequired;
}
