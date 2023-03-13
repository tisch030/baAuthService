package eu.firmax.cms.auth.idp;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * {@link IdentityProviderCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineIdentityProviderCache implements IdentityProviderCache {

    private static final String IDENTITY_PROVIDER_CACHE_KEY = "identityProviders";

    @NonNull
    private final LoadingCache<String, List<IdentityProvider>> identityProviders;

    @NonNull
    private final LoadingCache<String, String> identityProviderNameToIdMap;

    public CaffeineIdentityProviderCache(@NonNull final IdentityProviderLoadService identityProviderLoadService,
                                         @NonNull final IdentityProviderProperties identityProviderProperties) {
        identityProviders = Caffeine.newBuilder()
                .expireAfterAccess(identityProviderProperties.getIdentityProviderCacheDuration())
                .build(cacheKey -> identityProviderLoadService.loadIdentityProviders());

        identityProviderNameToIdMap = Caffeine.newBuilder()
                .expireAfterAccess(identityProviderProperties.getIdentityProviderCacheDuration())
                .build(identityProviderLoadService::loadIdentityProviderId);
    }

    @Override
    @NonNull
    public List<IdentityProvider> getIdentityProviders() {
        return identityProviders.get(IDENTITY_PROVIDER_CACHE_KEY);
    }

    @NonNull
    public String getIdentityProviderId(@NonNull final String identityProviderName) {
        return identityProviderNameToIdMap.get(identityProviderName);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        identityProviders.invalidateAll();
        identityProviderNameToIdMap.invalidateAll();
    }

}
