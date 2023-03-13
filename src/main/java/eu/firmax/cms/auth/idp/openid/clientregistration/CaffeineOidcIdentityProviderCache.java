package eu.firmax.cms.auth.idp.openid.clientregistration;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.openid.OidcIdentityProviderProperties;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@link OidcIdentityProviderCache} implementation which uses {@link Caffeine} as the concrete cache.
 * Clears the cache upon receiving a {@link AuthenticationConfigurationUpdatedEvent}.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineOidcIdentityProviderCache implements OidcIdentityProviderCache {

    private final static String OIDC_IDENTITY_PROVIDERS_CACHE_KEY = "clientRegistrationsMap";

    @NonNull
    private final LoadingCache<String, Map<String, ClientRegistration>> oidcClientRegistrations;

    public CaffeineOidcIdentityProviderCache(@NonNull final ClientRegistrationService clientRegistrationService,
                                             @NonNull final OidcIdentityProviderProperties oidcIdentityProviderProperties) {
        this.oidcClientRegistrations = Caffeine.newBuilder()
                .refreshAfterWrite(oidcIdentityProviderProperties.getRefreshMetadataInterval())
                .build(cacheKey -> clientRegistrationService.createClientRegistrations());
    }

    @Nullable
    @Override
    public ClientRegistration getOidcClientRegistrationByRegistrationId(@NonNull final String registrationId) {
        return oidcClientRegistrations.get(OIDC_IDENTITY_PROVIDERS_CACHE_KEY).get(registrationId);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        oidcClientRegistrations.invalidateAll();
    }
}
