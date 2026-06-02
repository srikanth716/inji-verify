package io.inji.verify.dto.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
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
    @JsonProperty("vct_values")
    @SerializedName("vct_values")
    private List<@NotBlank(message = "DCQL_META_INVALID") String> vctValues;

    /**
     * W3C VC (JSON-LD): expanded type values.
     */
    @JsonProperty("type_values")
    @SerializedName("type_values")
    private List<@NotBlank(message = "DCQL_META_INVALID") String> typeValues;
}
