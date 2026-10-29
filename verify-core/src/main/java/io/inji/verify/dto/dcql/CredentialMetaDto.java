package io.inji.verify.dto.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Represents the metadata of a credential in DCQL, including SD-JWT VC vct values, W3C VC expanded type values, and an ISO mdoc document type.")
public class CredentialMetaDto {

    /**
     * SD-JWT VC vct values
     */
    @JsonProperty("vct_values")
    @SerializedName("vct_values")
    @Size(min = 1, message = "DCQL_META_INVALID")
    @Schema(description = "List of vct values for SD-JWT verifiable credentials, used for matching against the credential's vct claim.")
    private List<@NotBlank(message = "DCQL_META_INVALID") String> vctValues;

    /**
     * W3C VC (JSON-LD): expanded type values.
     * OR-of-ANDs: each outer element is one alternative (OR); each inner array is a set of types
     * that must ALL be present in the credential's expanded type values (AND).
     */
    @JsonProperty("type_values")
    @SerializedName("type_values")
    @Size(min = 1, message = "DCQL_META_INVALID")
    @Schema(description = "Array of arrays of fully expanded type IRIs. Each inner array specifies a set of types that must ALL be present in the credential's type field (AND). At least one outer option must match (OR).")
    private List<
            @NotEmpty(message = "DCQL_META_INVALID")
            List<@NotBlank(message = "DCQL_META_INVALID") String>
            > typeValues;

    /**
     * ISO mdoc document type. Required when {@code format} is {@code mso_mdoc},
     * and forbidden on every other format. OpenID4VP 1.0 Appendix B.2.3.
     */
    @JsonProperty("doctype_value")
    @SerializedName("doctype_value")
    @Schema(description = "ISO mdoc only. Document type the wallet must present, for example org.iso.18013.5.1.mDL.")
    private String doctypeValue;
}
