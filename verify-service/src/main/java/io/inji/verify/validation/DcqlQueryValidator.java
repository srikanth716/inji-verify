package io.inji.verify.validation;

import io.inji.verify.dto.dcql.ClaimQueryDto;
import io.inji.verify.dto.dcql.CredentialMetaDto;
import io.inji.verify.dto.dcql.CredentialQueryDto;
import io.inji.verify.dto.dcql.CredentialSetQueryDto;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import io.inji.verify.enums.ErrorCode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates DCQL query structure for VP request creation.
 */
public final class DcqlQueryValidator {

    private static final Pattern CREDENTIAL_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "dc+sd-jwt",
            "vc+sd-jwt");

    private DcqlQueryValidator() {
    }

    public static ErrorCode validate(DCQLQueryDto dcqlQuery) {
        if (dcqlQuery == null) {
            return ErrorCode.DCQL_QUERY_REQUIRED;
        }

        List<CredentialQueryDto> credentials = dcqlQuery.getCredentials();
        if (credentials == null) {
            return ErrorCode.DCQL_CREDENTIALS_REQUIRED;
        }
        if (credentials.isEmpty()) {
            return ErrorCode.DCQL_CREDENTIALS_INVALID;
        }

        Set<String> credentialIds = new HashSet<>();
        for (CredentialQueryDto credential : credentials) {
            ErrorCode credentialError = validateCredential(credential, credentialIds);
            if (credentialError != null) {
                return credentialError;
            }
        }

        List<CredentialSetQueryDto> credentialSets = dcqlQuery.getCredentialSets();
        if (credentialSets != null && !credentialSets.isEmpty()) {
            ErrorCode credentialSetsError = validateCredentialSets(credentialSets, credentialIds);
            if (credentialSetsError != null) {
                return credentialSetsError;
            }
        }

        return null;
    }

    private static ErrorCode validateCredential(CredentialQueryDto credential, Set<String> credentialIds) {
        if (credential == null) {
            return ErrorCode.DCQL_VALIDATION_ERROR;
        }

        String credentialId = credential.getId();
        if (credentialId == null || credentialId.isBlank()) {
            return ErrorCode.DCQL_CREDENTIAL_ID_REQUIRED;
        }
        credentialId = credentialId.trim();
        if (!CREDENTIAL_ID_PATTERN.matcher(credentialId).matches()) {
            return ErrorCode.DCQL_CREDENTIAL_ID_INVALID;
        }
        if (!credentialIds.add(credentialId)) {
            return ErrorCode.DCQL_DUPLICATE_CREDENTIAL_ID;
        }

        String formatValue = credential.getFormat();
        if (formatValue == null || formatValue.isBlank()) {
            return ErrorCode.DCQL_CREDENTIAL_FORMAT_REQUIRED;
        }
        formatValue = formatValue.trim();
        if (!isSupportedFormat(formatValue)) {
            return ErrorCode.DCQL_CREDENTIAL_FORMAT_UNSUPPORTED;
        }

        CredentialMetaDto meta = credential.getMeta();
        if (meta == null) {
            return ErrorCode.DCQL_META_REQUIRED;
        }
        ErrorCode metaError = validateMeta(meta);
        if (metaError != null) {
            return metaError;
        }

        List<ClaimQueryDto> claims = credential.getClaims();
        List<List<String>> claimSets = credential.getClaimSets();
        if (claims != null && !claims.isEmpty()) {
        ErrorCode claimsError = validateClaims(claims, claimSets != null && !claimSets.isEmpty());
            if (claimsError != null) {
                return claimsError;
            }
        } else if (claimSets != null && !claimSets.isEmpty()) {
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }

        if (claimSets != null && !claimSets.isEmpty()) {
            ErrorCode claimSetsError = validateClaimSets(claimSets, claims);
            if (claimSetsError != null) {
                return claimSetsError;
            }
        }

        return null;
    }

    private static ErrorCode validateMeta(CredentialMetaDto meta) {
        ErrorCode vctValuesError = validateStringList(meta.getVctValues(), ErrorCode.INVALID_META_STRUCTURE);
        if (vctValuesError != null) {
            return vctValuesError;
        }

        return validateStringList(meta.getDoctypeValues(), ErrorCode.INVALID_META_STRUCTURE);
    }

    private static ErrorCode validateClaims(List<ClaimQueryDto> claims, boolean claimSetsPresent) {
        Set<String> claimIds = new HashSet<>();
        for (ClaimQueryDto claim : claims) {
            if (claim == null) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }

            String claimId = claim.getId();
            if (claimSetsPresent) {
                if (claimId == null || claimId.isBlank()) {
                    return ErrorCode.DCQL_CLAIM_ID_REQUIRED;
                }
                if (!claimIds.add(claimId.trim())) {
                    return ErrorCode.INVALID_CLAIMS_STRUCTURE;
                }
            } else if (claimId != null && claimId.isBlank()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }

            List<String> path = claim.getPath();
            if (path == null || path.isEmpty()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }
            ErrorCode pathError = validateClaimPath(path);
            if (pathError != null) {
                return pathError;
            }
        }

        return null;
    }

    private static ErrorCode validateClaimPath(List<String> path) {
        for (String pathElement : path) {
            if (pathElement == null) {
                continue;
            }
            if (pathElement.isBlank()) {
                return ErrorCode.INVALID_CLAIMS_STRUCTURE;
            }
        }
        return null;
    }

    private static ErrorCode validateClaimSets(List<List<String>> claimSets, List<ClaimQueryDto> claims) {
        if (claimSets.isEmpty()) {
            return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
        }
        if (claims == null || claims.isEmpty()) {
            return ErrorCode.INVALID_CLAIMS_STRUCTURE;
        }

        Set<String> claimIds = new HashSet<>();
        for (ClaimQueryDto claim : claims) {
            if (claim != null && claim.getId() != null && !claim.getId().isBlank()) {
                claimIds.add(claim.getId().trim());
            }
        }

        for (List<String> claimSet : claimSets) {
            if (claimSet == null || claimSet.isEmpty()) {
                return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
            }
            for (String claimId : claimSet) {
                if (claimId == null || claimId.isBlank()) {
                    return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
                }
                if (!claimIds.contains(claimId.trim())) {
                    return ErrorCode.INVALID_CLAIM_SETS_STRUCTURE;
                }
            }
        }
        return null;
    }

    private static ErrorCode validateCredentialSets(
            List<CredentialSetQueryDto> credentialSets,
            Set<String> credentialIds) {
        for (CredentialSetQueryDto credentialSet : credentialSets) {
            if (credentialSet == null) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            String credentialSetId = credentialSet.getId();
            if (credentialSetId == null || credentialSetId.isBlank()) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            List<List<String>> options = credentialSet.getOptions();
            if (options == null || options.isEmpty()) {
                return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
            }

            for (List<String> option : options) {
                if (option == null || option.isEmpty()) {
                    return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                }
                for (String credentialId : option) {
                    if (credentialId == null || credentialId.isBlank()) {
                        return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                    }
                    if (!credentialIds.contains(credentialId.trim())) {
                        return ErrorCode.INVALID_CREDENTIAL_SETS_STRUCTURE;
                    }
                }
            }
        }
        return null;
    }

    private static ErrorCode validateStringList(List<String> values, ErrorCode errorCode) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        for (String value : values) {
            if (value == null || value.isBlank()) {
                return errorCode;
            }
        }
        return null;
    }

    private static boolean isSupportedFormat(String format) {
        return SUPPORTED_FORMATS.stream().anyMatch(supported -> supported.equalsIgnoreCase(format));
    }
}
