package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Base interface for classes/interfaces which implement a cache for {@link RelyingPartyRegistration}s.
 */
public interface SamlIdentityProviderCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns a {@link RelyingPartyRegistration} with the given id.
     *
     * @param registrationId The id of the {@link RelyingPartyRegistration} which should be returned.
     * @return a {@link RelyingPartyRegistration} with the given id.
     */
    @Nullable
    RelyingPartyRegistration getSamlRelyingPartyRegistrationByRegistrationId(@NonNull final String registrationId);
}
