package io.inji.verify.validation;

import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.enums.ErrorCode;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates DCQL query structure for VP request creation.
 */
public final class DcqlQueryValidator {

    private static final Pattern CREDENTIAL_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "dc+sd-jwt",
            "vc+sd-jwt",
            "mso_mdoc");

    private DcqlQueryValidator() {
    }

    public static ErrorCode validate(JsonNode dcqlQuery) {
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

        Set<String> credentialIds = new HashSet<>();
        for (JsonNode credential : credentials) {
            ErrorCode credentialError = validateCredential(credential, credentialIds);
            if (credentialError != null) {
                return credentialError;
            }
        }

        JsonNode credentialSets = dcqlQuery.get("credential_sets");
        if (credentialSets != null && !credentialSets.isNull()) {
            ErrorCode credentialSetsError = validateCredentialSets(credentialSets, credentialIds);
            if (credentialSetsError != null) {
                return credentialSetsError;
            }
        }

        return null;
    }

    private static ErrorCode validateCredential(JsonNode credential, Set<String> credentialIds) {
        if (credential == null || !credential.isObject()) {
            return ErrorCode.DCQL_VALIDATION_ERROR;
        }

        JsonNode id = credential.get("id");
        if (id == null || !id.isTextual() || id.asText().isBlank()) {
            return ErrorCode.DCQL_CREDENTIAL_ID_REQUIRED;
        }
        String credentialId = id.asText().trim();
        if (!CREDENTIAL_ID_PATTERN.matcher(credentialId).matches()) {
            return ErrorCode.DCQL_CREDENTIAL_ID_INVALID;
        }
        if (!credentialIds.add(credentialId)) {
            return ErrorCode.DCQL_DUPLICATE_CREDENTIAL_ID;
        }

        JsonNode format = credential.get("format");
        if (format == null || !format.isTextual() || format.asText().isBlank()) {
            return ErrorCode.DCQL_CREDENTIAL_FORMAT_REQUIRED;
        }
        String formatValue = format.asText().trim();
        if (!isSupportedFormat(formatValue)) {
            return ErrorCode.DCQL_CREDENTIAL_FORMAT_UNSUPPORTED;
        }

        JsonNode multiple = credential.get("multiple");
        if (multiple != null && !multiple.isNull() && !multiple.isBoolean()) {
            return ErrorCode.DCQL_VALIDATION_ERROR;
        }

        JsonNode meta = credential.get("meta");
        if (meta == null || meta.isNull() || !meta.isObject()) {
            return ErrorCode.DCQL_META_REQUIRED;
        }
        ErrorCode metaError = validateMeta(meta, formatValue);
        if (metaError != null) {
            return metaError;
        }

        JsonNode trustedAuthorities = credential.get("trusted_authorities");
        if (trustedAuthorities != null && !trustedAuthorities.isNull()) {
            ErrorCode trustedAuthoritiesError = validateTrustedAuthorities(trustedAuthorities);
            if (trustedAuthoritiesError != null) {
                return trustedAuthoritiesError;
            }
        }

        JsonNode requireHolderBinding = credential.get("require_cryptographic_holder_binding");
        if (requireHolderBinding != null && !requireHolderBinding.isNull() && !requireHolderBinding.isBoolean()) {
            return ErrorCode.DCQL_VALIDATION_ERROR;
        }

        JsonNode claims = credential.get("claims");
        JsonNode claimSets = credential.get("claim_sets");
        if (claims != null && !claims.isNull()) {
            ErrorCode claimsError = validateClaims(claims, formatValue, claimSets != null && !claimSets.isNull());
            if (claimsError != null) {
                return claimsError;
            }
        } else if (claimSets != null && !claimSets.isNull()) {
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }

        if (claimSets != null && !claimSets.isNull()) {
            ErrorCode claimSetsError = validateClaimSets(claimSets, claims);
            if (claimSetsError != null) {
                return claimSetsError;
            }
        }

        return null;
    }

    private static ErrorCode validateMeta(JsonNode meta, String format) {
        ErrorCode vctValuesError = validateStringArrayField(meta.get("vct_values"), ErrorCode.INVALID_META_STRUCTURE);
        if (vctValuesError != null) {
            return vctValuesError;
        }

        JsonNode doctypeValue = meta.get("doctype_value");
        if (doctypeValue != null && !doctypeValue.isNull()
                && (!doctypeValue.isTextual() || doctypeValue.asText().isBlank())) {
            return ErrorCode.INVALID_META_STRUCTURE;
        }

        JsonNode typeValues = meta.get("type_values");
        if (typeValues != null && !typeValues.isNull()) {
            if (!typeValues.isArray()) {
                return ErrorCode.INVALID_META_STRUCTURE;
            }
            for (JsonNode typeValueSet : typeValues) {
                if (!typeValueSet.isArray() || typeValueSet.isEmpty()) {
                    return ErrorCode.INVALID_META_STRUCTURE;
                }
                for (JsonNode typeValue : typeValueSet) {
                    if (!typeValue.isTextual() || typeValue.asText().isBlank()) {
                        return ErrorCode.INVALID_META_STRUCTURE;
                    }
                }
            }
        }

        if ("mso_mdoc".equalsIgnoreCase(format)) {
            if (doctypeValue == null || doctypeValue.isNull() || doctypeValue.asText().isBlank()) {
                return ErrorCode.DCQL_DOCTYPE_VALUE_REQUIRED;
            }
        }

        return null;
    }

    private static ErrorCode validateTrustedAuthorities(JsonNode trustedAuthorities) {
        if (!trustedAuthorities.isArray()) {
            return ErrorCode.INVALID_TRUSTED_AUTHORITIES_STRUCTURE;
        }
        for (JsonNode authority : trustedAuthorities) {
            if (authority == null || !authority.isObject()) {
                return ErrorCode.INVALID_TRUSTED_AUTHORITIES_STRUCTURE;
            }
            JsonNode type = authority.get("type");
            if (type == null || !type.isTextual() || type.asText().isBlank()) {
                return ErrorCode.INVALID_TRUSTED_AUTHORITIES_STRUCTURE;
            }
            ErrorCode valuesError = validateStringArrayField(authority.get("values"), ErrorCode.INVALID_TRUSTED_AUTHORITIES_STRUCTURE);
            if (valuesError != null) {
                return valuesError;
            }
        }
        return null;
    }

    private static ErrorCode validateClaims(JsonNode claims, String format, boolean claimSetsPresent) {
        if (!claims.isArray()) {
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }

        Set<String> claimIds = new HashSet<>();
        for (JsonNode claim : claims) {
            if (claim == null || !claim.isObject()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }

            JsonNode claimId = claim.get("id");
            if (claimSetsPresent) {
                if (claimId == null || !claimId.isTextual() || claimId.asText().isBlank()) {
                    return ErrorCode.DCQL_CLAIM_ID_REQUIRED;
                }
                if (!claimIds.add(claimId.asText().trim())) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
            } else if (claimId != null && !claimId.isNull()) {
                if (!claimId.isTextual() || claimId.asText().isBlank()) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
            }

            JsonNode path = claim.get("path");
            if (path == null || !path.isArray() || path.isEmpty()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }
            ErrorCode pathError = validateClaimPath(path, format);
            if (pathError != null) {
                return pathError;
            }

            JsonNode values = claim.get("values");
            if (values != null && !values.isNull() && !values.isArray()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }
        }

        return null;
    }

    private static ErrorCode validateClaimPath(JsonNode path, String format) {
        if ("mso_mdoc".equalsIgnoreCase(format)) {
            if (path.size() != 2) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }
            for (JsonNode pathElement : path) {
                if (!pathElement.isTextual() || pathElement.asText().isBlank()) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
            }
            return null;
        }

        for (JsonNode pathElement : path) {
            if (pathElement.isNull()) {
                continue;
            }
            if (pathElement.isTextual()) {
                if (pathElement.asText().isBlank()) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
                continue;
            }
            if (pathElement.isIntegralNumber() && pathElement.longValue() >= 0) {
                continue;
            }
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }
        return null;
    }

    private static ErrorCode validateClaimSets(JsonNode claimSets, JsonNode claims) {
        if (!claimSets.isArray() || claimSets.isEmpty()) {
            return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
        }
        if (claims == null || !claims.isArray() || claims.isEmpty()) {
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }

        Set<String> claimIds = new HashSet<>();
        for (JsonNode claim : claims) {
            JsonNode claimId = claim.get("id");
            if (claimId != null && claimId.isTextual() && !claimId.asText().isBlank()) {
                claimIds.add(claimId.asText().trim());
            }
        }

        for (JsonNode claimSet : claimSets) {
            if (!claimSet.isArray() || claimSet.isEmpty()) {
                return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
            }
            for (JsonNode claimIdNode : claimSet) {
                if (!claimIdNode.isTextual() || claimIdNode.asText().isBlank()) {
                    return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
                }
                if (!claimIds.contains(claimIdNode.asText().trim())) {
                    return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
                }
            }
        }
        return null;
    }

    private static ErrorCode validateCredentialSets(JsonNode credentialSets, Set<String> credentialIds) {
        if (!credentialSets.isArray() || credentialSets.isEmpty()) {
            return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
        }

        for (JsonNode credentialSet : credentialSets) {
            if (credentialSet == null || !credentialSet.isObject()) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            JsonNode options = credentialSet.get("options");
            if (options == null || !options.isArray() || options.isEmpty()) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            JsonNode required = credentialSet.get("required");
            if (required != null && !required.isNull() && !required.isBoolean()) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            for (JsonNode option : options) {
                if (!option.isArray() || option.isEmpty()) {
                    return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                }
                for (JsonNode credentialIdNode : option) {
                    if (!credentialIdNode.isTextual() || credentialIdNode.asText().isBlank()) {
                        return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                    }
                    if (!credentialIds.contains(credentialIdNode.asText().trim())) {
                        return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                    }
                }
            }
        }
        return null;
    }

    private static ErrorCode validateStringArrayField(JsonNode arrayNode, ErrorCode errorCode) {
        if (arrayNode == null || arrayNode.isNull()) {
            return null;
        }
        if (!arrayNode.isArray() || arrayNode.isEmpty()) {
            return errorCode;
        }
        for (JsonNode value : arrayNode) {
            if (!value.isTextual() || value.asText().isBlank()) {
                return errorCode;
            }
        }
        return null;
    }

    private static boolean isSupportedFormat(String format) {
        return SUPPORTED_FORMATS.stream().anyMatch(supported -> supported.equalsIgnoreCase(format));
    }
}
