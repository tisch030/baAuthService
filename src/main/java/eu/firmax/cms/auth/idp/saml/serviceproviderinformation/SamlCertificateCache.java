package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKey;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

/**
 * Base interface for classes/interfaces which implement a cache for {@link CertificateAndPrivateKey}.
 * The certificate is published and known by the SAML identity providers and the key pair
 * is used to sign SAML requests or to decrypt SAML responses.
 */
public interface SamlCertificateCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the {@link CertificateAndPrivateKey} combination.
     *
     * @return the {@link CertificateAndPrivateKey} combination.
     */
    @NonNull
    CertificateAndPrivateKey getSamlCertificate();

}
