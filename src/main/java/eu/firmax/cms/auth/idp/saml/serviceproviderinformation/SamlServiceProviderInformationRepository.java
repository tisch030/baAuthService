package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;

/**
 * Base interface for classes/interfaces which implement a repository for SAML certificate and private key pairs.
 * The certificate is published and known by the SAML identity providers and the key pair
 * is used to sign or encrypt SAML requests or to decrypt SAML responses.
 */
public interface SamlServiceProviderInformationRepository {

    /**
     * Returns the SAML certificate and private key pair.
     *
     * @return the SAML certificate and private key pair.
     */
    @Nullable
    CertificateAndPrivateKeyInPEMFormat getCertificateInformation();

    /**
     * Updates the stored SAML certificate and private key pair.
     *
     * @param certificateAndPrivateKeyInPEMFormat the new certificate and private key pair which will be stored.
     */
    void saveCertificateInformation(@NonNull final CertificateAndPrivateKeyInPEMFormat certificateAndPrivateKeyInPEMFormat);
}
