package eu.firmax.cms.auth.client;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * {@link RegisteredClientCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineRegisteredClientCache implements RegisteredClientCache {

    private static final String CLIENT_REGISTRATIONS_CACHE_KEY = "clientRegistrationMap";

    @NonNull
    private final LoadingCache<String, Map<String, RegisteredClient>> clientRegistrationToIdMap;


    public CaffeineRegisteredClientCache(@NonNull final RegisteredClientService registeredClientService,
                                         @NonNull final RegisteredClientProperties registeredClientProperties) {
        this.clientRegistrationToIdMap = Caffeine.newBuilder()
                .refreshAfterWrite(registeredClientProperties.getRefreshClientsInterval())
                .build(cacheKey -> registeredClientService.registerClients());
    }

    @Override
    @Nullable
    public RegisteredClient getRegisteredClientById(@NonNull String registeredClientId) {
        return clientRegistrationToIdMap.get(CLIENT_REGISTRATIONS_CACHE_KEY).get(registeredClientId);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        clientRegistrationToIdMap.invalidateAll();
    }
}
