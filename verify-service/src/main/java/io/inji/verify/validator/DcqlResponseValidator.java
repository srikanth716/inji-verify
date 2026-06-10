package io.inji.verify.validator;

import static io.inji.verify.utils.Utils.extractClaims;
import static io.inji.verify.utils.Utils.isSdJwt;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.inji.verify.dto.authorizationrequest.AuthorizationRequestResponseDto;
import io.inji.verify.dto.dcql.ClaimQueryDto;
import io.inji.verify.dto.dcql.CredentialMetaDto;
import io.inji.verify.dto.dcql.CredentialQueryDto;
import io.inji.verify.dto.dcql.CredentialSetQueryDto;
import io.inji.verify.dto.dcql.DCQLQueryDto;
import io.inji.verify.dto.result.DcqlTokensDto;
import io.inji.verify.dto.result.ValidationResult;
import io.inji.verify.exception.InvalidCredentialException;
import io.inji.verify.exception.InvalidVpTokenException;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import lombok.extern.slf4j.Slf4j;

/**
 * Validates a VP token submission against a DCQL query.
 *
 * Pipeline:
 *  For each submitted presentation (LDP-VP, LDP-VC, SD-JWT):
 *    Steps 1–5 are DISCARD checks — failing any one silently drops that presentation.
 *    1. Credential ID   — must exist in dcql.credentials[].id
 *    2. Format          — presentation format must match query format
 *    3. Meta            — vct_values (SD-JWT) or type_values (LDP-VC) must match
 *    4. Claims          — required claim paths must be present and values must match
 *    5. Claim Sets      — at least one claim_set option must be fully satisfied
 *
 *  After discarding invalid presentations:
 *    Steps 6–7 are REJECT checks — failing any one rejects the entire VP token.
 *    6. Multiple        — if multiple=false, only one valid presentation is allowed per credential
 *    7. Credential Sets — all required credential_sets must have at least one satisfied option
 */
@Component
@Slf4j
public class DcqlResponseValidator {

    private final List<String> claimsWithMetaData;
    private final PixelPass pixelPass;

    public DcqlResponseValidator(
            @Value("${inji.verify.claims-with-meta-data}") List<String> claimsWithMetaData,
            PixelPass pixelPass) {
        this.claimsWithMetaData = claimsWithMetaData;
        this.pixelPass = pixelPass;
    }

    public ValidationResult validate(AuthorizationRequestResponseDto authRequest, DcqlTokensDto tokens) {
        if (authRequest == null || authRequest.getDcqlQuery() == null) {
            return ValidationResult.fail("invalid_vp_token: DCQL query is missing from the authorization request");
        }
        if (tokens == null) {
            return ValidationResult.fail("invalid_vp_token: vp_token is missing or could not be parsed");
        }

        DCQLQueryDto dcqlQuery = authRequest.getDcqlQuery();

        // Build a lookup: credential id → its query definition
        Map<String, CredentialQueryDto> queryById = new HashMap<>();
        for (CredentialQueryDto cq : dcqlQuery.getCredentials()) {
            queryById.put(cq.getId(), cq);
        }

        // Steps 1–5: for every submitted presentation, try to match it against its
        // query. Count how many valid presentations survive per credential id.
        // Also track the first discard reason per credential id for error reporting.
        Map<String, Integer> validCounts = new HashMap<>();
        Map<String, String> firstDiscardReason = new HashMap<>();

        collectValidCounts(tokens.getLdpVpTokens(), queryById, validCounts, firstDiscardReason,
                (query, vp) -> discardCheck(query, vp, null, null));
        collectValidCounts(tokens.getLdpVcTokens(), queryById, validCounts, firstDiscardReason,
                (query, vc) -> discardCheck(query, null, vc, null));
        collectValidCounts(tokens.getSdJwtTokens(), queryById, validCounts, firstDiscardReason,
                (query, jwt) -> discardCheck(query, null, null, jwt));

        return evaluateCredentialSets(dcqlQuery, validCounts, firstDiscardReason, collectSubmittedIds(tokens));
    }

    @FunctionalInterface
    private interface PresentationDiscardCheck<T> {
        String check(CredentialQueryDto query, T presentation);
    }

    private <T> void collectValidCounts(
            Map<String, List<T>> tokensById,
            Map<String, CredentialQueryDto> queryById,
            Map<String, Integer> validCounts,
            Map<String, String> firstDiscardReason,
            PresentationDiscardCheck<T> discardCheck) {
        if (tokensById == null) {
            return;
        }
        for (Map.Entry<String, List<T>> entry : tokensById.entrySet()) {
            String id = entry.getKey();
            CredentialQueryDto query = queryById.get(id);
            if (query == null) {
                log.debug("Ignoring unknown credential id '{}' in vp_token", id);
                continue;
            }
            scorePresentations(id, entry.getValue(), query, validCounts, firstDiscardReason,
                    presentation -> discardCheck.check(query, presentation));
        }
    }

    private <T> void scorePresentations(
            String credentialId,
            List<T> presentations,
            CredentialQueryDto query,
            Map<String, Integer> validCounts,
            Map<String, String> firstDiscardReason,
            java.util.function.Function<T, String> checker) {
        if (presentations == null || presentations.isEmpty()) {
            return;
        }

        if (!allowsMultiple(query) && presentations.size() > 1) {
            firstDiscardReason.put(credentialId, String.format(
                    "invalid_vp_token: credential '%s' requires a single presentation but %d were submitted",
                    credentialId, presentations.size()));
            return;
        }

        int validCount = 0;
        for (T presentation : presentations) {
            String reason = checker.apply(presentation);
            if (reason == null) {
                validCount++;
            } else {
                firstDiscardReason.putIfAbsent(credentialId, reason);
            }
        }
        if (validCount > 0) {
            validCounts.merge(credentialId, validCount, Integer::sum);
            firstDiscardReason.remove(credentialId);
        }
    }

    /** Returns null if valid; otherwise the discard reason. */
    private String discardCheck(CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        String formatFailure = checkFormat(query, ldpVp, ldpVc, sdJwt);
        if (formatFailure != null) {
            return formatFailure;
        }
        String metaFailure = checkMeta(query, ldpVp, ldpVc, sdJwt);
        if (metaFailure != null) {
            return metaFailure;
        }
        return checkClaims(query, ldpVp, ldpVc, sdJwt);
    }

    private String checkFormat(CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        String format = query.getFormat();
        String id = query.getId();

        if ("ldp_vc".equals(format)) {
            if (ldpVp != null && hasType(ldpVp, "VerifiablePresentation")) return null;
            if (ldpVc != null && hasType(ldpVc, "VerifiableCredential")
                    && Boolean.FALSE.equals(query.getRequire_cryptographic_holder_binding())) return null;
            if (sdJwt != null)
                return "invalid_vp_token: credential '" + id + "' requires an LDP Verifiable Presentation but an SD-JWT was submitted";
            if (ldpVp != null)
                return "invalid_vp_token: credential '" + id + "' requires a VerifiablePresentation but the submitted presentation does not have type VerifiablePresentation";
            return "invalid_vp_token: credential '" + id + "' requires a VerifiableCredential but the submitted credential does not have type VerifiableCredential";
        }

        if (isSdJwtFormat(format)) {
            if (sdJwt == null)
                return "invalid_vp_token: credential '" + id + "' requires format " + format + " but an LDP Verifiable Presentation was submitted";
            if (!isSdJwt(sdJwt))
                return "invalid_vp_token: credential '" + id + "' requires a valid SD-JWT presentation";
            String typ = readSdJwtTyp(sdJwt);
            if (!format.equals(typ))
                return "invalid_vp_token: credential '" + id + "' requires format " + format + " but submitted SD-JWT has typ '" + (typ.isEmpty() ? "unknown" : typ) + "'";
            return null;
        }

        return "invalid_vp_token: credential '" + id + "' has unsupported format '" + format + "'";
    }

    private String checkMeta(CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        CredentialMetaDto meta = query.getMeta();
        String id = query.getId();

        if (meta == null) {
            return "invalid_vp_token: credential '" + id + "' is missing required DCQL meta configuration";
        }

        if (isSdJwtFormat(query.getFormat())) {
            List<String> vctValues = meta.getVctValues();
            if (vctValues == null || vctValues.isEmpty()) return null;
            String vct = readSdJwtVct(sdJwt);
            if (vct == null || vct.isBlank())
                return "invalid_vp_token: credential '" + id + "' requires vct in " + vctValues + " but submitted SD-JWT has no vct claim";
            if (!vctValues.contains(vct))
                return "invalid_vp_token: credential '" + id + "' vct '" + vct + "' does not match required vct_values " + vctValues;
            return null;
        }

        if ("ldp_vc".equals(query.getFormat())) {
            List<String> typeValues = meta.getTypeValues();
            if (typeValues == null || typeValues.isEmpty()) return null;
            Set<String> vcTypes = ldpVc != null ? extractNormalizedTypes(ldpVc) : extractNormalizedVcTypes(ldpVp);
            boolean allPresent = typeValues.stream().map(this::normalizeTypeValue).allMatch(vcTypes::contains);
            if (!allPresent)
                return "invalid_vp_token: credential '" + id + "' verifiable credential type does not match required type_values " + typeValues;
            return null;
        }

        return null;
    }

    private String checkClaims(CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        List<ClaimQueryDto> claimDefs = query.getClaims();
        if (claimDefs == null || claimDefs.isEmpty()) return null;

        // Extract flat claims map from credential
        Map<String, Object> claimsMap = extractClaimsMap(query, ldpVp, ldpVc, sdJwt);
        if (claimsMap == null) {
            return "invalid_vp_token: credential '" + query.getId() + "' claim validation failed: could not extract claims from credential";
        }

        List<List<String>> claimSets = query.getClaimSets();

        if (claimSets == null || claimSets.isEmpty()) {
            for (ClaimQueryDto claim : claimDefs) {
                String failure = claimFailure(query.getId(), claim, claimsMap);
                if (failure != null) {
                    return failure;
                }
            }
            return null;
        }

        for (List<String> claimSetOption : claimSets) {
            if (claimSetOptionSatisfied(query.getId(), claimDefs, claimSetOption, claimsMap)) {
                return null;
            }
        }
        return "invalid_vp_token: credential '" + query.getId() + "' claim validation failed: none of the required claim_sets options are satisfied";
    }

    private Map<String, Object> extractClaimsMap(
            CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        String credentialString = resolveCredentialString(query, ldpVp, ldpVc, sdJwt);
        if (credentialString == null) return null;
        try {
            return extractClaims(credentialString, toCredentialFormat(query.getFormat()), claimsWithMetaData, pixelPass);
        } catch (InvalidCredentialException e) {
            return null;
        }
    }

    private String claimFailure(String credentialId, ClaimQueryDto claim, Map<String, Object> claimsMap) {
        Object value = resolveClaimValue(claim, claimsMap);
        String claimRef = claim.getId() != null ? claim.getId() : String.valueOf(claim.getPath());
        if (value == null) {
            return "invalid_vp_token: credential '" + credentialId + "' claim '" + claimRef + "' at path " + claim.getPath() + " was not found in the submitted credential";
        }
        if (claim.getValues() != null && !claim.getValues().isEmpty()
                && claim.getValues().stream().noneMatch(expected -> valuesMatch(expected, value))) {
            return "invalid_vp_token: credential '" + credentialId + "' claim '" + claimRef + "' value '" + value + "' does not match required values " + claim.getValues();
        }
        return null;
    }

    private boolean claimSetOptionSatisfied(
            String credentialId,
            List<ClaimQueryDto> claimDefs,
            List<String> claimSetOption,
            Map<String, Object> claimsMap) {
        for (String claimId : claimSetOption) {
            ClaimQueryDto claim = findClaimById(claimDefs, claimId);
            if (claim == null || claimFailure(credentialId, claim, claimsMap) != null) {
                return false;
            }
        }
        return true;
    }

    private ValidationResult evaluateCredentialSets(
            DCQLQueryDto dcqlQuery,
            Map<String, Integer> validCounts,
            Map<String, String> firstDiscardReason,
            Set<String> submittedIds) {

        List<CredentialSetQueryDto> credentialSets = dcqlQuery.getCredentialSets();

        if (credentialSets == null || credentialSets.isEmpty()) {
            for (CredentialQueryDto cq : dcqlQuery.getCredentials()) {
                if (!hasValidPresentations(validCounts, cq.getId())) {
                    return rejectReason(cq.getId(), firstDiscardReason, submittedIds);
                }
            }
            return ValidationResult.ok();
        }

        for (CredentialSetQueryDto credSet : credentialSets) {
            if (!credSet.isRequired()) continue;

            boolean satisfied = credSet.getOptions().stream()
                    .anyMatch(option -> option.stream().allMatch(id -> hasValidPresentations(validCounts, id)));

            if (!satisfied) {
                return resolveSetFailureReason(credSet, validCounts, firstDiscardReason, submittedIds);
            }
        }
        return ValidationResult.ok();
    }

    private ValidationResult resolveSetFailureReason(
            CredentialSetQueryDto credSet,
            Map<String, Integer> validCounts,
            Map<String, String> firstDiscardReason,
            Set<String> submittedIds) {

        for (List<String> option : credSet.getOptions()) {
            for (String id : option) {
                if (hasValidPresentations(validCounts, id)) continue;
                String reason = firstDiscardReason.get(id);
                if (reason != null) return ValidationResult.fail(reason);
            }
        }
        for (List<String> option : credSet.getOptions()) {
            for (String id : option) {
                if (!hasValidPresentations(validCounts, id) && !submittedIds.contains(id)) {
                    return rejectReason(id, firstDiscardReason, submittedIds);
                }
            }
        }
        String optionsDescription = credSet.getOptions().stream()
                .map(option -> "[" + String.join(", ", option) + "]")
                .reduce((l, r) -> l + " OR " + r)
                .orElse("[]");
        return ValidationResult.fail(
                "invalid_vp_token: required credential_set not satisfied; at least one of " + optionsDescription + " must be fully satisfied");
    }

    private ValidationResult rejectReason(
            String credentialId, Map<String, String> firstDiscardReason, Set<String> submittedIds) {
        String reason = firstDiscardReason.get(credentialId);
        if (reason != null) return ValidationResult.fail(reason);
        if (!submittedIds.contains(credentialId))
            return ValidationResult.fail("invalid_vp_token: required credential '" + credentialId + "' was not included in vp_token");
        return ValidationResult.fail("invalid_vp_token: submitted presentation for credential '" + credentialId + "' does not satisfy the DCQL query");
    }

    private Object resolveClaimValue(ClaimQueryDto claim, Map<String, Object> claimsMap) {
        List<String> path = claim.getPath();
        if (path == null || path.isEmpty()) return null;
        List<String> effectivePath = (!path.isEmpty() && "credentialSubject".equals(path.get(0)))
                ? path.subList(1, path.size())
                : path;
        return navigatePath(claimsMap, effectivePath);
    }

    private Object navigatePath(Object current, List<String> path) {
        if (path.isEmpty()) return current;
        if (current == null) return null;

        String segment = path.getFirst();
        List<String> rest = path.subList(1, path.size());

        if (segment == null || "null".equalsIgnoreCase(segment)) {
            return navigateWildcard(current, rest);
        }
        if (current instanceof Map<?, ?> map) return navigatePath(map.get(segment), rest);
        if (current instanceof JSONObject obj) return navigatePath(obj.opt(segment), rest);
        if (current instanceof JSONArray arr) return navigateIndex(arr, segment, rest);
        if (current instanceof List<?> list) return navigateIndex(list, segment, rest);
        return null;
    }

    private Object navigateWildcard(Object current, List<String> rest) {
        if (current instanceof JSONArray arr) {
            for (int i = 0; i < arr.length(); i++) {
                Object found = navigatePath(arr.get(i), rest);
                if (found != null) return found;
            }
        } else if (current instanceof List<?> list) {
            for (Object item : list) {
                Object found = navigatePath(item, rest);
                if (found != null) return found;
            }
        }
        return null;
    }

    private Object navigateIndex(Object collection, String segment, List<String> rest) {
        try {
            int index = Integer.parseInt(segment);
            Object element;
            if (collection instanceof JSONArray arr) {
                if (index < 0 || index >= arr.length()) return null;
                element = arr.get(index);
            } else if (collection instanceof List<?> list) {
                if (index < 0 || index >= list.size()) return null;
                element = list.get(index);
            } else {
                return null;
            }
            return navigatePath(element, rest);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private boolean hasValidPresentations(Map<String, Integer> validCounts, String credentialId) {
        return validCounts.getOrDefault(credentialId, 0) > 0;
    }

    private boolean allowsMultiple(CredentialQueryDto query) {
        return query != null && Boolean.TRUE.equals(query.getMultiple());
    }

    private boolean isSdJwtFormat(String format) {
        return "dc+sd-jwt".equals(format) || "vc+sd-jwt".equals(format);
    }

    private boolean hasType(JSONObject obj, String expectedType) {
        Object types = obj.opt("type");
        if (types instanceof JSONArray arr) {
            for (Object t : arr) if (expectedType.equalsIgnoreCase(t.toString())) return true;
            return false;
        }
        if (types instanceof String s) return expectedType.equalsIgnoreCase(s);
        return false;
    }

    private boolean valuesMatch(Object expected, Object actual) {
        if (expected == null) return actual == null;
        if (actual == null) return false;
        if (expected instanceof Boolean eb) {
            if (actual instanceof Boolean ab) return eb.equals(ab);
            return eb.equals(Boolean.parseBoolean(String.valueOf(actual)));
        }
        if (expected instanceof Number en && actual instanceof Number an)
            return en.doubleValue() == an.doubleValue();
        return Objects.equals(String.valueOf(expected), String.valueOf(actual));
    }

    private ClaimQueryDto findClaimById(List<ClaimQueryDto> claims, String id) {
        return claims.stream().filter(c -> id.equals(c.getId())).findFirst().orElse(null);
    }

    private Set<String> collectSubmittedIds(DcqlTokensDto tokens) {
        Set<String> ids = new HashSet<>();
        if (tokens.getLdpVpTokens() != null) ids.addAll(tokens.getLdpVpTokens().keySet());
        if (tokens.getLdpVcTokens() != null) ids.addAll(tokens.getLdpVcTokens().keySet());
        if (tokens.getSdJwtTokens() != null) ids.addAll(tokens.getSdJwtTokens().keySet());
        return ids;
    }

    private String resolveCredentialString(
            CredentialQueryDto query, JSONObject ldpVp, JSONObject ldpVc, String sdJwt) {
        if (isSdJwtFormat(query.getFormat())) return sdJwt;
        if (ldpVc != null) return ldpVc.toString();
        if (ldpVp == null) return null;
        List<Object> creds = getListOfVerifiableCredentials(ldpVp.opt("verifiableCredential"));
        return creds.isEmpty() ? null : creds.getFirst().toString();
    }

    private CredentialFormat toCredentialFormat(String format) {
        return switch (format) {
            case "dc+sd-jwt" -> CredentialFormat.DC_SD_JWT;
            case "vc+sd-jwt" -> CredentialFormat.VC_SD_JWT;
            default -> CredentialFormat.LDP_VC;
        };
    }

    private Set<String> extractNormalizedVcTypes(JSONObject ldpVp) {
        if (ldpVp == null) return Set.of();
        try {
            List<Object> creds = getListOfVerifiableCredentials(ldpVp.opt("verifiableCredential"));
            return creds.isEmpty() ? Set.of() : extractNormalizedTypes(new JSONObject(creds.getFirst().toString()));
        } catch (Exception e) {
            log.debug("Failed to extract VC types from VP", e);
            return Set.of();
        }
    }

    private Set<String> extractNormalizedTypes(JSONObject obj) {
        Set<String> types = new HashSet<>();
        Object typeField = obj.opt("type");
        if (typeField instanceof JSONArray arr) {
            for (Object item : arr) types.add(normalizeTypeValue(item.toString()));
        } else if (typeField != null) {
            types.add(normalizeTypeValue(typeField.toString()));
        }
        return types;
    }

    private String normalizeTypeValue(String v) {
        if (v == null) return "";
        int hash = v.lastIndexOf('#');
        return (hash >= 0 && hash < v.length() - 1) ? v.substring(hash + 1) : v;
    }

    private String readSdJwtTyp(String sdJwt) {
        try {
            String header = new String(Base64.getUrlDecoder().decode(sdJwt.split("~")[0].split("\\.")[0]));
            return new JSONObject(header).optString("typ", "");
        } catch (Exception e) { return ""; }
    }

    private String readSdJwtVct(String sdJwt) {
        try {
            String payload = new String(Base64.getUrlDecoder().decode(sdJwt.split("~")[0].split("\\.")[1]));
            return new JSONObject(payload).optString("vct", null);
        } catch (Exception e) { return null; }
    }

    private List<Object> getListOfVerifiableCredentials(Object vc) {
        if (vc instanceof JSONArray arr) {
            if (arr.isEmpty()) throw new InvalidVpTokenException();
            List<Object> list = new ArrayList<>();
            for (Object c : arr) list.add(c);
            return list;
        }
        if (vc instanceof JSONObject || vc instanceof String) return List.of(vc);
        throw new InvalidVpTokenException();
    }
}