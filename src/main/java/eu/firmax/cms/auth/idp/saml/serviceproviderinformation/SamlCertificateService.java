package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKey;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import eu.firmax.cms.auth.rsa.RsaUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;

/**
 * Service that handles the creation and loading of certificate and private key pairs.
 * Used to fill the {@link SamlCertificateCache}.
 */
@Service
@RequiredArgsConstructor
public class SamlCertificateService {

    @NonNull
    private final SamlIdentityProviderProperties samlIdentityProviderProperties;

    @NonNull
    private final SamlServiceProviderInformationRepository samlServiceProviderInformationRepository;

    /**
     * Retrieves the configured {@link CertificateAndPrivateKey}.
     * Will return a newly created combination of {@link CertificateAndPrivateKey},
     * if no configured {@link CertificateAndPrivateKey} could be found.
     *
     * @return a {@link CertificateAndPrivateKey}.
     */
    @NonNull
    public CertificateAndPrivateKey loadOrCreateCertificateAndPrivateKey() {
        // Load certificate and private key.
        final CertificateAndPrivateKeyInPEMFormat certificateInformation = samlServiceProviderInformationRepository.getCertificateInformation();

        if (certificateInformation != null) {
            // Already got a certificate, no need to generate a new one.
            return RsaUtils.transformFromPEM(certificateInformation);
        }

        // Generate new certificate and corresponding private key if no certificate information could be found.
        final CertificateAndPrivateKey generatedCertificateInformation = RsaUtils.generateNewKeyPair(
                samlIdentityProviderProperties.getCertificateValidityDuration(),
                samlIdentityProviderProperties.getCertificatePrivateKeyKeySize(),
                samlIdentityProviderProperties.getCertificateX509DistinguishedName(),
                samlIdentityProviderProperties.getCertificateSignatureAlgorithm(),
                OffsetDateTime.now(Clock.systemUTC()));

        // Save generated certificate and private key for future use.
        samlServiceProviderInformationRepository.saveCertificateInformation(RsaUtils.transformToPEM(generatedCertificateInformation));

        return generatedCertificateInformation;
    }
}
