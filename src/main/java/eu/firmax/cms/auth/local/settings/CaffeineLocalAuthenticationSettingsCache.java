package eu.firmax.cms.auth.local.settings;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.local.LocalAuthenticationProperties;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * {@link LocalAuthenticationSettingsCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineLocalAuthenticationSettingsCache implements LocalAuthenticationSettingsCache {

    private static final String LOCAL_AUTHENTICATION_SETTINGS_CACHE_KEY = "localAuthenticationSettings";

    @NonNull
    private final LoadingCache<String, LocalAuthenticationSettings> localAuthenticationSettings;

    public CaffeineLocalAuthenticationSettingsCache(@NonNull final LocalAuthenticationSettingsService localAuthenticationSettingsService,
                                                    @NonNull final LocalAuthenticationProperties localAuthenticationProperties) {
        localAuthenticationSettings = Caffeine.newBuilder()
                .expireAfterAccess(localAuthenticationProperties.getLocalAuthenticationSettingsCacheDuration())
                .build(cacheKey -> localAuthenticationSettingsService.loadLocalAuthenticationSettings());
    }

    @Nullable
    @Override
    public LocalAuthenticationSettings getLocalAuthenticationSettings() {
        return localAuthenticationSettings.get(LOCAL_AUTHENTICATION_SETTINGS_CACHE_KEY);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        localAuthenticationSettings.invalidateAll();
    }
}
