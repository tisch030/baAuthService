package eu.firmax.cms.auth.idp.saml.samlsettings;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.idp.saml.relyingpartyregistration.SamlIdentityProviderRepository;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@link SamlSettingsCache} implementation which uses {@link Caffeine} as the concrete cache.
 * Clears the cache upon receiving a {@link AuthenticationConfigurationUpdatedEvent}.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineSamlSettingsCache implements SamlSettingsCache {

    private final static String SAML_SETTINGS_CACHE_KEY = "samlSettingsMap";

    @NonNull
    private final LoadingCache<String, Map<String, SamlIdentityProviderRepository.SamlProviderSettings>> samlProviderSettings;

    public CaffeineSamlSettingsCache(@NonNull final SamlSettingsLoadService samlSettingsLoadService,
                                     @NonNull final SamlIdentityProviderProperties samlIdentityProviderProperties) {

        samlProviderSettings = Caffeine.newBuilder()
                .expireAfterAccess(samlIdentityProviderProperties.getRefreshSamlSettingsInterval())
                .build(cacheKey -> samlSettingsLoadService.loadSamlSettings());
    }

    @Override
    @NonNull
    public SamlIdentityProviderRepository.SamlProviderSettings getSamlProviderSettings(@NonNull final String samlIdentityProviderRegistrationId) {
        return samlProviderSettings.get(SAML_SETTINGS_CACHE_KEY).get(samlIdentityProviderRegistrationId);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        samlProviderSettings.invalidateAll();
    }
}
