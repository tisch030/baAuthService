package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Glue code to forward any spring request for {@link JWK}s to the {@link JwkSetCache}.
 */
@Component
@RequiredArgsConstructor
public class JwkSource implements JWKSource<SecurityContext> {

    @NonNull
    private final JwkSetCache jwkSetCache;

    @Override
    public List<JWK> get(@NonNull final JWKSelector jwkSelector,
                         @Nullable final SecurityContext context) throws KeySourceException {
        final JWKSet jwks = jwkSetCache.getJwkSet();
        return jwkSelector.select(jwks);
    }
}
