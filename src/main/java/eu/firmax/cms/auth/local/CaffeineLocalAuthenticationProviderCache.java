package eu.firmax.cms.auth.local;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.local.database.DatabaseAuthenticationService;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.stereotype.Component;

/**
 * {@link LocalAuthenticationProviderCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineLocalAuthenticationProviderCache implements LocalAuthenticationProviderCache {

    private static final String LOCAL_AUTHENTICATION_PROVIDER_CACHE_KEY = "localAuthProvider";

    @NonNull
    private final LoadingCache<String, AuthenticationProvider> authenticationProvider;

    public CaffeineLocalAuthenticationProviderCache(@NonNull final DatabaseAuthenticationService databaseAuthenticationService,
                                                    @NonNull final LocalAuthenticationProperties localAuthenticationProperties) {
        authenticationProvider = Caffeine.newBuilder()
                .expireAfterAccess(localAuthenticationProperties.getAuthenticationProviderInstanceCacheDuration())
                .build(cacheKey -> databaseAuthenticationService.createDatabaseAuthenticationProvider());
    }

    @Nullable
    @Override
    public AuthenticationProvider getLocalAuthenticationProvider() {
        return authenticationProvider.get(LOCAL_AUTHENTICATION_PROVIDER_CACHE_KEY);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        authenticationProvider.invalidateAll();
    }
}
