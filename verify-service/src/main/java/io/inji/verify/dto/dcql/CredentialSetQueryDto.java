package io.inji.verify.dto.dcql;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSetQueryDto {

    /**
     * Each inner list contains credential ids.
     */
    @NotNull(message = "DCQL_CREDENTIAL_SETS_REQUIRED")
    private List<List<String>> options;

    private boolean required = true;
}
