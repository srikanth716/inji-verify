package api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    private VerifiableClaimsConfigManager() {
    }

    public static synchronized void init() {
        if (initialized) {
            return;
        }
        try {
            JsonNode config = loadConfigJson();
            try {
                credentialIdToName = buildCredentialIdToNameMap(config);
            } catch (RuntimeException remoteOrPrimaryFailure) {
                // Remote config may return 200 with a different/empty schema; fall back to bundled config.
                LOGGER.warn("Primary config.json could not be used (" + remoteOrPrimaryFailure.getMessage()
                        + "). Falling back to classpath resource.");
                credentialIdToName = buildCredentialIdToNameMap(readJsonFromClasspath(FALLBACK_CONFIG_RESOURCE));
            }
            initialized = true;
            LOGGER.info("Loaded " + credentialIdToName.size() + " verifiable claim(s) from config.json");
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
        String configuredKey = InjiVerifyConfigManager.getproperty("uiAuto.credential.essential");
        if (configuredKey != null && !configuredKey.trim().isEmpty()) {
            if (credentialIdToName.containsKey(configuredKey.trim())) {
                return credentialIdToName.get(configuredKey.trim());
            }
            return getCredentialName(configuredKey.trim());
        }
        for (Map.Entry<String, String> entry : credentialIdToName.entrySet()) {
            // essential credential is typically mosip_verifiable_credential_id in default config
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

    private static JsonNode loadConfigJson() throws IOException {
        String configuredUrl = InjiVerifyConfigManager.getproperty("uiAuto.configJsonUrl");
        if (configuredUrl != null && !configuredUrl.trim().isEmpty()) {
            return readJsonFromUrl(configuredUrl.trim());
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
        HttpURLConnection connection = (HttpURLConnection) new URL(configUrl).openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(15000);
        connection.setRequestProperty("Accept", "application/json");

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException("Failed to fetch config.json from " + configUrl + ". HTTP status: " + responseCode);
        }

        try (InputStream inputStream = connection.getInputStream()) {
            return OBJECT_MAPPER.readTree(inputStream);
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

    private static Map<String, String> buildCredentialIdToNameMap(JsonNode config) {
        JsonNode verifiableClaims = config.path("verifiableClaims");
        if (!verifiableClaims.isArray()) {
            throw new RuntimeException("config.json is missing verifiableClaims array");
        }

        Map<String, String> idToName = new HashMap<>();
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
            for (JsonNode credential : credentials) {
                String credentialId = credential.path("id").asText(null);
                if (credentialId != null && !credentialId.trim().isEmpty()) {
                    idToName.put(credentialId.trim(), displayName.trim());
                }
            }
        }

        if (idToName.isEmpty()) {
            throw new RuntimeException("No credential definitions found in config.json verifiableClaims");
        }
        return Collections.unmodifiableMap(idToName);
    }

    static void resetForTests() {
        initialized = false;
        credentialIdToName = Collections.emptyMap();
    }
}
