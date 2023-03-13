package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@link SamlIdentityProviderCache} implementation which uses {@link Caffeine} as the concrete cache.
 * Clears the cache upon receiving a {@link AuthenticationConfigurationUpdatedEvent}.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineSamlIdentityProviderCache implements SamlIdentityProviderCache {

    private final static String SAML_IDENTITY_PROVIDER_CACHE_KEY = "relyingPartyRegistrationsMap";

    @NonNull
    private final LoadingCache<String, Map<String, RelyingPartyRegistration>> samlIdentityProviders;

    public CaffeineSamlIdentityProviderCache(@NonNull final RelyingPartyRegistrationService relyingPartyRegistrationService,
                                             @NonNull final SamlIdentityProviderProperties samlIdentityProviderProperties) {
        this.samlIdentityProviders = Caffeine.newBuilder()
                .refreshAfterWrite(samlIdentityProviderProperties.getRefreshMetadataInterval())
                .build(cacheKey -> relyingPartyRegistrationService.createRelyingPartyRegistrations());
    }

    @Nullable
    @Override
    public RelyingPartyRegistration getSamlRelyingPartyRegistrationByRegistrationId(@NonNull final String registrationId) {
        return samlIdentityProviders.get(SAML_IDENTITY_PROVIDER_CACHE_KEY).get(registrationId);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        samlIdentityProviders.invalidateAll();
    }
}
