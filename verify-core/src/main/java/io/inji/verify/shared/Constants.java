package io.inji.verify.shared;

import io.inji.verify.dto.client.LdpVp;
import io.inji.verify.dto.client.VpFormats;
import io.inji.verify.dto.client.SdJwt;

import java.util.Arrays;
import java.util.List;

public final class Constants {

    private Constants() {
    }

    private static final List<String> SD_JWT_SUPPORTED_ALGORITHMS = Arrays.asList(
            "RS256",
            "ES256",
            "ES256K",
            "EdDSA");

    public static final int DEFAULT_EXPIRY = 300;

    public static final String RESPONSE_SUBMISSION_URI_ROOT = "/vp-submission";
    public static final String RESPONSE_SUBMISSION_URI = "/direct-post";
    public static final String VP_DEFINITION_URI = "/vp-definition/";
    public static final String VP_REQUEST_URI = "/vp-request";
    public static final String RESPONSE_TYPE =  "vp_token";
    public static final String RESPONSE_MODE =  "direct_post";
    public static final String COOKIE_NAME = "transaction_id";

    public static final String TRANSACTION_ID_PREFIX = "txn";
    public static final String REQUEST_ID_PREFIX = "req";

    // client_id scheme prefixes (OpenID4VP). A clientId starting with one of these triggers the
    // by-reference (request_uri) signed-JWT flow; the prefix also dictates which JWT header the
    // signed request must use.
    public static final String CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER = "decentralized_identifier";
    public static final String CLIENT_ID_PREFIX_X509_SAN_DNS = "x509_san_dns";

    // Fixed symbolic `aud` value for Self-Issued OpenID Provider v2 (Static Discovery), per
    // OpenID4VP 1.0 5.8: mandatory on every signed Request Object we produce, since we have no
    // way to negotiate Dynamic Discovery with a wallet (that requires the POST-based Request URI
    // Method's wallet_metadata, which we don't implement). Not configurable — this is a spec-fixed
    // constant, not deployment-specific data.
    public static final String AUD_SELF_ISSUED = "https://self-issued.me/v2";
    public static final String RSA_SIGNATURE_2018 = "RsaSignature2018";
    public static final String ED25519_SIGNATURE_2018 = "Ed25519Signature2018";
    public static final String ED25519_SIGNATURE_2020 = "Ed25519Signature2020";
    public static final VpFormats VP_FORMATS = new VpFormats(new LdpVp(Arrays.asList(
            ED25519_SIGNATURE_2018,
            ED25519_SIGNATURE_2020,
            RSA_SIGNATURE_2018
    )), new SdJwt(SD_JWT_SUPPORTED_ALGORITHMS,
            SD_JWT_SUPPORTED_ALGORITHMS));

    // JSON KEYS
    public static final String KEY_PROOF = "proof";
    public static final String KEY_TYPE = "type";
    public static final String KEY_JWS = "jws";
    public static final String KEY_VERIFICATION_METHOD = "verificationMethod";
    public static final String KEY_VERIFIABLE_CREDENTIAL = "verifiableCredential";
    public static final String KEY_CREDENTIAL = "credential";

    // STATUS PURPOSE
    public static final String STATUS_PURPOSE_REVOKED = "revocation";
}
