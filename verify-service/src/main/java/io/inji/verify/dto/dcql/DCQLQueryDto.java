package io.inji.verify.dto.dcql;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DCQLQueryDto {

    @Valid
    @NotNull(message = "DCQL_CREDENTIALS_REQUIRED")
    @NotEmpty(message = "DCQL_CREDENTIALS_INVALID")
    private List<CredentialQueryDto> credentials;

    @Valid
    @JsonProperty("credential_sets")
    @SerializedName("credential_sets")
    private List<CredentialSetQueryDto> credentialSets;
}
