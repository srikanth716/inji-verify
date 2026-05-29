package io.inji.verify.dto.dcql;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DCQLQueryDto {

    @Valid
    @NotNull(message = "DCQL_CREDENTIALS_REQUIRED")
    @NotEmpty(message = "DCQL_CREDENTIALS_INVALID")
    private List<CredentialQueryDto> credentials;

    @Valid
    private List<CredentialSetQueryDto> credentialSets;
}
