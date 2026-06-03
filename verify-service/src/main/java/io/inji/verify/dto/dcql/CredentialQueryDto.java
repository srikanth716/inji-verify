package io.inji.verify.dto.dcql;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialQueryDto {

    @NotBlank(message = "DCQL_CREDENTIAL_ID_REQUIRED")
    private String id;

    /**
     * vc+sd-jwt, dc+sd-jwt etc.
     */
    @NotBlank(message = "DCQL_CREDENTIAL_FORMAT_REQUIRED")
    private String format;

    @Valid
    @NotNull(message = "DCQL_META_REQUIRED")
    private CredentialMetaDto meta;

    @Valid
    private List<ClaimQueryDto> claims;

    /**
     * References claim ids.
     */
    @JsonProperty("claim_sets")
    @SerializedName("claim_sets")
    private List<List<String>> claimSets;
}
