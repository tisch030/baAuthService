package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * {@link SamlServiceProviderMetadataCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineSamlServiceProviderMetadataCache implements SamlServiceProviderMetadataCache {

    private final static String SAML_SERVICE_PROVIDER_METADATA_CACHE_KEY = "samlMetaData";

    @NonNull
    private final LoadingCache<String, SamlServiceProviderMetadata> samlServiceProviderMetadata;

    public CaffeineSamlServiceProviderMetadataCache(@NonNull final SamlServiceProviderMetadataService samlServiceProviderMetadataService,
                                                    @NonNull final SamlIdentityProviderProperties samlIdentityProviderProperties) {
        this.samlServiceProviderMetadata = Caffeine.newBuilder()
                .expireAfterAccess(samlIdentityProviderProperties.getRefreshMetadataInterval())
                .build(cacheKey -> samlServiceProviderMetadataService.loadSamlServiceProviderMetadata());
    }

    @Override
    @NonNull
    public SamlServiceProviderMetadata getMetadata() {
        return samlServiceProviderMetadata.get(SAML_SERVICE_PROVIDER_METADATA_CACHE_KEY);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        samlServiceProviderMetadata.invalidateAll();
    }
}
