package io.inji.verify.dto.dcql;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DCQLQueryDto {

    @Valid
    private List<CredentialQueryDto> credentials;

    @Valid
    private List<CredentialSetQueryDto> credentialSets;
}
