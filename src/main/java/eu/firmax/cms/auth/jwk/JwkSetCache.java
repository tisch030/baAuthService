package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

/**
 * Base interface for classes/interfaces which implement a cache for {@link JWKSet}s.
 */
public interface JwkSetCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the cached {@link JWKSet}.
     *
     * @return the cached {@link JWKSet}.
     */
    @NonNull
    JWKSet getJwkSet();
}
