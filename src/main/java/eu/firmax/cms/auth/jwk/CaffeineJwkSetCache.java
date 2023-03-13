package eu.firmax.cms.auth.jwk;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.nimbusds.jose.jwk.JWKSet;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedEvent;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * {@link JwkSetCache} implementation which uses {@link Caffeine} as the concrete cache.
 */
@Component
@ConditionalOnClass(Caffeine.class)
public class CaffeineJwkSetCache implements JwkSetCache {

    private static final String JWK_CACHE_KEY = "jwkSet";

    @NonNull
    private final LoadingCache<String, JWKSet> jwkSets;

    public CaffeineJwkSetCache(@NonNull final JwksService jwksService,
                               @NonNull final JwkProperties jwkProperties) {
        this.jwkSets = Caffeine.newBuilder()
                .refreshAfterWrite(jwkProperties.getRefreshJwksInterval())
                .expireAfterAccess(jwkProperties.getJwksCacheDuration())
                .build(cacheKey -> jwksService.loadOrCreateJwkSet());
    }

    @Override
    @NonNull
    public JWKSet getJwkSet() {
        return jwkSets.get(JWK_CACHE_KEY);
    }

    @Override
    @EventListener
    public void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event) {
        jwkSets.invalidateAll();
    }
}
