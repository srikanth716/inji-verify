package io.inji.verify.dto.dcql;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialMetaDto {

    /**
     * SD-JWT VC vct values
     */
    private List<@NotBlank(message = "DCQL_META_INVALID") String> vctValues;

    /**
     * W3C VC (JSON-LD): expanded type values.
     */
    private List<@NotBlank(message = "DCQL_META_INVALID") String> typeValues;
}
