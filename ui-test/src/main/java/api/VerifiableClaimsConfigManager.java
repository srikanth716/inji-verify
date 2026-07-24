package api;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.testrig.apirig.utils.RestClient;
import io.restassured.response.Response;

/**
 * Loads verify-ui {@code config.json} and resolves credential display names used in VP selection UI.
 * Credential keys in {@code injiVerify.properties} map to DCQL credential ids; display names come from config.
 */
public final class VerifiableClaimsConfigManager {

    private static final Logger LOGGER = Logger.getLogger(VerifiableClaimsConfigManager.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String CREDENTIAL_KEY_PREFIX = "uiAuto.credential.";
    private static final String FALLBACK_CONFIG_RESOURCE = "config/config.json";

    private static volatile boolean initialized;
    private static volatile Map<String, String> credentialIdToName = Collections.emptyMap();
    private static volatile String essentialCredentialId;

    private VerifiableClaimsConfigManager() {
    }

    public static synchronized void init() {
        if (initialized) {
            return;
        }
        try {
            JsonNode config = loadConfigJson();
            try {
                applyConfig(config);
            } catch (RuntimeException remoteOrPrimaryFailure) {
                // Remote config may return 200 with a different/empty schema; fall back to bundled config.
                LOGGER.warn("Primary config.json could not be used (" + remoteOrPrimaryFailure.getMessage()
                        + "). Falling back to classpath resource.");
                applyConfig(readJsonFromClasspath(FALLBACK_CONFIG_RESOURCE));
            }
            initialized = true;
            LOGGER.info("Loaded " + credentialIdToName.size() + " verifiable claim(s) from config.json"
                    + (essentialCredentialId != null ? "; essential=" + essentialCredentialId : ""));
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize verifiable claims config", e);
        }
    }

    public static String getCredentialName(String credentialKey) {
        ensureInitialized();
        String credentialId = InjiVerifyConfigManager.getproperty(CREDENTIAL_KEY_PREFIX + credentialKey);
        if (credentialId == null || credentialId.trim().isEmpty()) {
            throw new RuntimeException("Missing property '" + CREDENTIAL_KEY_PREFIX + credentialKey
                    + "' in injiVerify.properties");
        }
        return getCredentialNameById(credentialId.trim());
    }

    public static String getCredentialNameById(String credentialId) {
        ensureInitialized();
        String name = credentialIdToName.get(credentialId);
        if (name == null || name.trim().isEmpty()) {
            throw new RuntimeException("Credential id '" + credentialId + "' not found in config.json verifiableClaims");
        }
        return name;
    }

    public static String getEssentialCredentialName() {
        ensureInitialized();

        // Prefer config.json's own essential:true marker so tests track app config.
        if (essentialCredentialId != null && !essentialCredentialId.trim().isEmpty()) {
            String propertyId = InjiVerifyConfigManager.getproperty("uiAuto.credential.essential");
            if (propertyId != null && !propertyId.trim().isEmpty()
                    && !propertyId.trim().equals(essentialCredentialId.trim())) {
                LOGGER.warn("uiAuto.credential.essential='" + propertyId.trim()
                        + "' differs from config.json essential credential id='" + essentialCredentialId.trim()
                        + "'. Using config.json value.");
            }
            return getCredentialNameById(essentialCredentialId.trim());
        }

        // Fall back to property as a DCQL credential id (not a short key suffix).
        String configuredId = InjiVerifyConfigManager.getproperty("uiAuto.credential.essential");
        if (configuredId != null && !configuredId.trim().isEmpty()) {
            return getCredentialNameById(configuredId.trim());
        }

        for (Map.Entry<String, String> entry : credentialIdToName.entrySet()) {
            if ("mosip_verifiable_credential_id".equals(entry.getKey())) {
                return entry.getValue();
            }
        }
        throw new RuntimeException("No essential credential found in config.json");
    }

    private static void ensureInitialized() {
        if (!initialized) {
            init();
        }
    }

    private static void applyConfig(JsonNode config) {
        MapBuildResult result = buildCredentialIdToNameMap(config);
        credentialIdToName = result.idToName;
        essentialCredentialId = result.essentialCredentialId;
    }

    private static JsonNode loadConfigJson() throws IOException {
        String configuredUrl = InjiVerifyConfigManager.getproperty("uiAuto.configJsonUrl");
        if (configuredUrl != null && !configuredUrl.trim().isEmpty()) {
            try {
                return readJsonFromUrl(configuredUrl.trim());
            } catch (IOException e) {
                LOGGER.warn("Unable to fetch config.json from uiAuto.configJsonUrl. Falling back to classpath resource. "
                        + e.getMessage());
            }
        }

        String injiVerifyUrl = InjiVerifyConfigManager.getInjiVerifyUi();
        if (injiVerifyUrl != null && !injiVerifyUrl.trim().isEmpty()) {
            String normalizedBase = injiVerifyUrl.trim();
            if (!normalizedBase.endsWith("/")) {
                normalizedBase = normalizedBase + "/";
            }
            try {
                return readJsonFromUrl(normalizedBase + "assets/config.json");
            } catch (IOException e) {
                LOGGER.warn("Unable to fetch config.json from deployed inji-verify UI. Falling back to classpath resource. "
                        + e.getMessage());
            }
        }

        return readJsonFromClasspath(FALLBACK_CONFIG_RESOURCE);
    }

    private static JsonNode readJsonFromUrl(String configUrl) throws IOException {
        try {
            Response response = RestClient.getRequest(configUrl, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
            if (response == null) {
                throw new IOException("Empty response fetching config.json from " + configUrl);
            }
            int statusCode = response.getStatusCode();
            if (statusCode != 200) {
                throw new IOException("Failed to fetch config.json from " + configUrl + ". HTTP status: " + statusCode);
            }
            String body = response.getBody() != null ? response.getBody().asString() : null;
            if (body == null || body.trim().isEmpty()) {
                throw new IOException("Empty body fetching config.json from " + configUrl);
            }
            return OBJECT_MAPPER.readTree(body);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to fetch config.json from " + configUrl + ": " + e.getMessage(), e);
        }
    }

    private static JsonNode readJsonFromClasspath(String resourcePath) throws IOException {
        InputStream inputStream = VerifiableClaimsConfigManager.class.getClassLoader().getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new IOException("Classpath config resource not found: " + resourcePath);
        }
        try (InputStream stream = inputStream) {
            return OBJECT_MAPPER.readTree(stream);
        }
    }

    private static MapBuildResult buildCredentialIdToNameMap(JsonNode config) {
        JsonNode verifiableClaims = config.path("verifiableClaims");
        if (!verifiableClaims.isArray()) {
            throw new RuntimeException("config.json is missing verifiableClaims array");
        }

        Map<String, String> idToName = new HashMap<>();
        String essentialId = null;
        Iterator<JsonNode> claims = verifiableClaims.elements();
        while (claims.hasNext()) {
            JsonNode claim = claims.next();
            String displayName = claim.path("name").asText(null);
            if (displayName == null || displayName.trim().isEmpty()) {
                continue;
            }

            JsonNode credentials = claim.path("dcqlQuery").path("credentials");
            if (!credentials.isArray()) {
                continue;
            }
            boolean claimIsEssential = claim.path("essential").asBoolean(false);
            for (JsonNode credential : credentials) {
                String credentialId = credential.path("id").asText(null);
                if (credentialId == null || credentialId.trim().isEmpty()) {
                    continue;
                }
                String trimmedId = credentialId.trim();
                String trimmedName = displayName.trim();
                String previousName = idToName.put(trimmedId, trimmedName);
                if (previousName != null && !previousName.equals(trimmedName)) {
                    LOGGER.warn("Duplicate DCQL credential id '" + trimmedId
                            + "' in config.json verifiableClaims. Overwriting display name '"
                            + previousName + "' with '" + trimmedName + "'.");
                }
                if (claimIsEssential) {
                    if (essentialId != null && !essentialId.equals(trimmedId)) {
                        LOGGER.warn("Multiple essential:true claims in config.json. Keeping '"
                                + essentialId + "', ignoring '" + trimmedId + "'.");
                    } else {
                        essentialId = trimmedId;
                    }
                }
            }
        }

        if (idToName.isEmpty()) {
            throw new RuntimeException("No credential definitions found in config.json verifiableClaims");
        }
        return new MapBuildResult(Collections.unmodifiableMap(idToName), essentialId);
    }

    private static final class MapBuildResult {
        private final Map<String, String> idToName;
        private final String essentialCredentialId;

        private MapBuildResult(Map<String, String> idToName, String essentialCredentialId) {
            this.idToName = idToName;
            this.essentialCredentialId = essentialCredentialId;
        }
    }

    static void resetForTests() {
        initialized = false;
        credentialIdToName = Collections.emptyMap();
        essentialCredentialId = null;
    }
}
