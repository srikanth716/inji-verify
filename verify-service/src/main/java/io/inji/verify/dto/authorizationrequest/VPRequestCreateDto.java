package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.enums.ErrorCode;
import io.inji.verify.validation.DcqlQueryValidator;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@AllArgsConstructor
@Getter
@NotNull
public class VPRequestCreateDto {
    private static final Set<String> LEGACY_PRESENTATION_DEFINITION_KEYS = Set.of(
            "presentationDefinition",
            "presentationDefinitionId",
            "presentation_definition",
            "presentation_definition_uri",
            "presentation_definition_id");

    @NotNull(message = "Client Id must not be null")
    @NotBlank(message = "Client Id must not be empty")
    String clientId;
    String transactionId;
    String nonce;
    JsonNode dcqlQuery;
    boolean acceptVPWithoutHolderProof;
    boolean responseCodeValidationRequired;

    @JsonIgnore
    private final Map<String, JsonNode> additionalProperties = new LinkedHashMap<>();

    @JsonAnySetter
    public void setAdditionalProperty(String name, JsonNode value) {
        additionalProperties.put(name, value);
    }

    public boolean hasLegacyPresentationDefinitionKeys() {
        return additionalProperties.keySet().stream().anyMatch(LEGACY_PRESENTATION_DEFINITION_KEYS::contains);
    }

    /**
     * Validates this VP request (client id, legacy keys, dcql_query presence and structure).
     *
     * @return first validation error, or null if valid
     */
    public ErrorCode validateRequest() {
        if (clientId == null || clientId.isBlank()) {
            return ErrorCode.CLIENT_ID_REQUIRED;
        }

        boolean hasLegacyKeys = hasLegacyPresentationDefinitionKeys();
        boolean hasDcqlQuery = dcqlQuery != null && !dcqlQuery.isNull();

        if (hasDcqlQuery && hasLegacyKeys) {
            return ErrorCode.AMBIGUOUS_QUERY;
        }

        if (hasLegacyKeys) {
            return ErrorCode.PRESENTATION_DEFINITION_NOT_SUPPORTED;
        }

        if (!hasDcqlQuery) {
            return ErrorCode.DCQL_QUERY_REQUIRED;
        }

        return validateDcqlQuery();
    }

    public ErrorCode validateDcqlQuery() {
        return DcqlQueryValidator.validate(dcqlQuery);
    }
}
