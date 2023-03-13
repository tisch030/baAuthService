package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Base interface for classes/interfaces which implement a cache for {@link ClientRegistration}s.
 */
public interface OidcIdentityProviderCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the cached {@link ClientRegistration} which matches the given id.
     *
     * @param registrationId The id of the {@link ClientRegistration} which should be returned.
     * @return the cached {@link ClientRegistration} which matches the given id.
     */
    @Nullable
    ClientRegistration getOidcClientRegistrationByRegistrationId(@NonNull final String registrationId);
}
