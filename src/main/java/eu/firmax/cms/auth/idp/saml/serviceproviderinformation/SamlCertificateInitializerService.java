package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Service for initializing the SAML certificate information on startup.
 */
@Component
@RequiredArgsConstructor
public class SamlCertificateInitializerService {

    @NonNull
    private final SamlCertificateCache samlCertificateCache;

    @PostConstruct
    public void init() {
        // Loading the certificate from the cache ensures that a new certificate is created if it should be missing.
        samlCertificateCache.getSamlCertificate();
    }
}
