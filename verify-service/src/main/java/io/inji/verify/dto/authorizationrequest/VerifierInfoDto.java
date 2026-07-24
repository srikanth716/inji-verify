package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Optional verifier identity and trust metadata for OpenID4VP Authorization Requests.
 * Attestations are opaque payloads — no schema or credential validation is applied.
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifierInfoDto {

    @JsonProperty("organization_name")
    private String organizationName;

    @JsonProperty("policy_uri")
    private String policyUri;

    private List<AttestationDto> attestations;

    public boolean hasContent() {
        return StringUtils.hasText(organizationName)
                || StringUtils.hasText(policyUri)
                || !CollectionUtils.isEmpty(attestations);
    }
}
