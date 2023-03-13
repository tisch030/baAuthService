package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import edu.umd.cs.findbugs.annotations.NonNull;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Service for initializing the {@link JWKSet}s.
 * Is primarily used to ensure the {@link JWKSet} are available at server start.
 */
@Component
@RequiredArgsConstructor
public class JwtInitializerService {

    @NonNull
    private final JwkSetCache jwkSetCache;

    @PostConstruct
    public void init() {
        // Loading the jwk sets from the cache ensures that a new jwk set is created if it should be missing.
        jwkSetCache.getJwkSet();
    }
}
