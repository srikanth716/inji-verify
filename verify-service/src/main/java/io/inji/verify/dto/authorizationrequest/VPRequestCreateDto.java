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
    @NotBlank(message = "CLIENT_ID_REQUIRED")
    String clientId;
    String transactionId;
    String nonce;
    @Valid
    @NotNull(message = "DCQL_QUERY_REQUIRED")
    private DCQLQueryDto dcqlQuery;
    boolean acceptVPWithoutHolderProof;
    boolean responseCodeValidationRequired;
}
