package io.inji.verify.dto.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

/**
 * {@code vp_formats_supported.mso_mdoc} per OpenID4VP 1.0 Appendix B.2.2.
 * Algorithm identifiers are COSE {@code alg} values.
 */
@AllArgsConstructor
@Getter
public class MsoMdoc {

    @JsonProperty("issuerauth_alg_values")
    @SerializedName("issuerauth_alg_values")
    private List<Integer> issuerAuthAlgValues;

    @JsonProperty("deviceauth_alg_values")
    @SerializedName("deviceauth_alg_values")
    private List<Integer> deviceAuthAlgValues;
}
