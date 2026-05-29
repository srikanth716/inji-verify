package io.inji.verify.dto.dcql;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialQueryDto {

    @NotBlank
    private String id;

    /**
     * vc+sd-jwt, dc+sd-jwt etc.
     */
    @NotBlank
    private String format;

    @Valid
    private CredentialMetaDto meta;

    @Valid
    private List<ClaimQueryDto> claims;

    /**
     * References claim ids.
     */
    @Valid
    private List<List<String>> claimSets;
}
