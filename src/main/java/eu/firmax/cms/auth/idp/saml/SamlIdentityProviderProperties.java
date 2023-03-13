package eu.firmax.cms.auth.idp.saml;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.time.Period;

/**
 * Configures the properties for the configuration of SAML identity providers and service providers.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "companyx.auth.idp.saml")
public class SamlIdentityProviderProperties {

    /**
     * Each SAML Identity Provider has metadata which is used to inform the service provider
     * about its URLs and certificates.
     * Since the certificates have limited validity periods and URLs can change, the metadata must be updated regularly,
     * although not in very short intervals.
     * The default value is one day.
     */
    private Duration refreshMetadataInterval = Duration.ofDays(1);

    /**
     * Cache duration of our own SAML certificate.
     * The default value is one day.
     */
    private Duration samlCertificateCacheDuration = Duration.ofDays(1);

    /**
     * Cache duration of the SAML identity provider settings.
     * The default value is one day.
     */
    private Duration refreshSamlSettingsInterval = Duration.ofDays(1);

    /**
     * Validity length for newly generated SAML certificates.
     * Should be at least one year.
     * The default value is five years.
     */
    private Period certificateValidityDuration = Period.ofYears(5);

    /**
     * Key size used for the private key.
     * Should be at least 2048. Higher values can increase CPU load.
     * The default value is 2048.
     */
    private int certificatePrivateKeyKeySize = 2048;

    /**
     * DistinguishedName used for the certificate.
     * The default value is "CN=companyx".
     */
    private String certificateX509DistinguishedName = "CN=companyx";

    /**
     * Signature algorithm used for the SAML requests.
     * The default value is "SHA256WithRSA".
     */
    private String certificateSignatureAlgorithm = "SHA256WithRSA";

    /**
     * The technical contact person's name that will be published as part of the SAML metadata.
     * The default value is "Companyx".
     */
    private String spMetadataTechnicalContactPersonName = "CompanyX";

    /**
     * The technical contact person's e-mail address that will be published as part of the SAML metadata.
     * The default value is "NutzerkontoBund@TestMail.eu".
     */
    private String spMetadataTechnicalContactPersonMail = "NutzerkontoBund@TestMail.eu";
}
