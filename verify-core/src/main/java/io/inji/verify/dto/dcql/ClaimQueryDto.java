package io.inji.verify.dto.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Represents a claim query in DCQL, specifying the path to the claim and optional values for matching.")
public class ClaimQueryDto {

    @Schema(description = "Unique identifier for the claim query, used for reference in credential sets.")
    private String id;

    @NotNull(message = "DCQL_CLAIM_PATH_REQUIRED")
    @Size(min = 1, message = "DCQL_CLAIM_PATH_INVALID")
    @Schema(description = "Path to the claim within the credential. For JSON credentials each element is a non-blank string, null (wildcard), or a non-negative integer. For mso_mdoc the path is exactly two strings: namespace, then element identifier.")
    private List<Object> path;

    @Schema(description = "Optional list of values to match against the claim value in the credential. If provided, the claim value in the credential must match one of these values for the query to be satisfied.")
    @Size(min = 1, message = "DCQL_CLAIM_VALUES_INVALID")
    private List<Object> values;

    /**
     * ISO 18013-5 IntentToRetain. Carried to the wallet on an {@code mso_mdoc} claim.
     * It is not a condition for accepting or rejecting the response. OpenID4VP 1.0 Appendix B.2.4.
     */
    @JsonProperty("intent_to_retain")
    @SerializedName("intent_to_retain")
    @Schema(description = "ISO mdoc only. Whether the verifier intends to retain this element. Carried to the wallet and never used to accept or reject the response.")
    private Boolean intentToRetain;
}
