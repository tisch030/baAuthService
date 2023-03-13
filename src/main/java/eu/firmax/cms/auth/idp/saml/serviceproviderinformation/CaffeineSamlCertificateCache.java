package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKey;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * {@link SamlCertificateCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineSamlCertificateCache implements SamlCertificateCache {

    private final static String SAML_SERVICE_PROVIDER_CERTIFICATE_CACHE_KEY = "samlCertificateAndKey";

    @NonNull
    private final LoadingCache<String, CertificateAndPrivateKey> samlCertificates;

    public CaffeineSamlCertificateCache(@NonNull final SamlCertificateService samlCertificateService,
                                        @NonNull final SamlIdentityProviderProperties samlIdentityProviderProperties) {
        this.samlCertificates = Caffeine.newBuilder()
                .expireAfterAccess(samlIdentityProviderProperties.getSamlCertificateCacheDuration())
                .build(cacheKey -> samlCertificateService.loadOrCreateCertificateAndPrivateKey());
    }

    @Override
    @NonNull
    public CertificateAndPrivateKey getSamlCertificate() {
        return samlCertificates.get(SAML_SERVICE_PROVIDER_CERTIFICATE_CACHE_KEY);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        samlCertificates.invalidateAll();
    }
}
