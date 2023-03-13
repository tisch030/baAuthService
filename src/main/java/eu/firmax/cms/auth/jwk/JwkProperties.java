package eu.firmax.cms.auth.jwk;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.time.Period;

/**
 * Configures the properties that relate to jwk set settings, which are used by our authorization server
 * to create encrypted access tokens.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.jwk")
public class JwkProperties {

    /**
     * Cache refresh duration of JWKs.
     * JWKs must be rotated regularly.
     * The default value is one day.
     */
    private Duration refreshJwksInterval = Duration.ofDays(1);

    /**
     * Cache duration of JWKs.
     * JWKs must be rotated regularly.
     * The default value is one day.
     */
    private Duration jwksCacheDuration = Duration.ofDays(1);

    /**
     * Our own JWK validity duration.
     * The default value is five years.
     */
    private Period certificateValidityDuration = Period.ofYears(5);

    /**
     * The private key size used by our own JWK.
     * Should be at least 2048. Higher values can increase CPU load.
     * The default value is 2048.
     */
    private int certificatePrivateKeyKeySize = 2048;

    /**
     * DistinguishedName used for the certificate of our own JWK.
     * The default value is "CN=companyx".
     */
    private String certificateX509DistinguishedName = "CN=companyx";

    /**
     * Signature algorithm used for the certificate of our own JWK.
     * The default value is "SHA256WithRSA".
     */
    private String certificateSignatureAlgorithm = "SHA256WithRSA";
}
