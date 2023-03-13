package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;

/**
 * Glue code to forward any spring request for {@link ClientRegistration}s to the {@link OidcIdentityProviderCache}.
 */
@Service
@RequiredArgsConstructor
public class DynamicClientRegistrationRepository implements ClientRegistrationRepository {

    @NonNull
    private final OidcIdentityProviderCache oidcIdentityProviderCache;

    @Override
    public ClientRegistration findByRegistrationId(@NonNull final String registrationId) {
        return oidcIdentityProviderCache.getOidcClientRegistrationByRegistrationId(registrationId);
    }
}
