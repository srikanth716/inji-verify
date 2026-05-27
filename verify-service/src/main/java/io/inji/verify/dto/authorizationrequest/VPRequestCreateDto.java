package io.inji.verify.dto.authorizationrequest;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.enums.ErrorCode;
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
        if (dcqlQuery == null || dcqlQuery.isNull()) {
            return ErrorCode.DCQL_QUERY_REQUIRED;
        }
        if (!dcqlQuery.isObject()) {
            return ErrorCode.DCQL_VALIDATION_ERROR;
        }

        JsonNode credentials = dcqlQuery.get("credentials");
        if (credentials == null) {
            return ErrorCode.DCQL_CREDENTIALS_REQUIRED;
        }
        if (!credentials.isArray() || credentials.isEmpty()) {
            return ErrorCode.DCQL_CREDENTIALS_INVALID;
        }

        for (JsonNode credential : credentials) {
            JsonNode id = credential.get("id");
            if (id == null || !id.isTextual() || id.asText().isBlank()) {
                return ErrorCode.DCQL_CREDENTIAL_ID_REQUIRED;
            }

            JsonNode format = credential.get("format");
            if (format == null || !format.isTextual() || format.asText().isBlank()) {
                return ErrorCode.DCQL_CREDENTIAL_FORMAT_REQUIRED;
            }
            if (!"dc+sd-jwt".equalsIgnoreCase(format.asText().trim())) {
                return ErrorCode.DCQL_CREDENTIAL_FORMAT_UNSUPPORTED;
            }

            JsonNode claims = credential.get("claims");
            if (claims != null) {
                if (!claims.isArray()) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
                for (JsonNode claim : claims) {
                    JsonNode path = claim.get("path");
                    if (path == null || !path.isArray() || path.isEmpty()) {
                        return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                    }
                    for (JsonNode pathElement : path) {
                        if (!pathElement.isTextual() || pathElement.asText().isBlank()) {
                            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                        }
                    }
                }
            }
        }

        return null;
    }
}
