package eu.firmax.cms.auth.local;

import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;
import org.springframework.security.authentication.AuthenticationProvider;

/**
 * Base interface for classes/interfaces which implement a cache for {@link AuthenticationProvider}s.
 */
public interface LocalAuthenticationProviderCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the {@link AuthenticationProvider} for local authentication (i.e. username/password) that is
     * cached.
     *
     * @return the {@link AuthenticationProvider} for local authentication (i.e. username/password) that is
     * cached.
     */
    @Nullable
    AuthenticationProvider getLocalAuthenticationProvider();
}
