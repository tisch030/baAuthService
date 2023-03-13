package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Glue code to forward any spring request for {@link RelyingPartyRegistration}s to the {@link SamlIdentityProviderCache}.
 */
@Component
@RequiredArgsConstructor
public class DynamicRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    @NonNull
    private final SamlIdentityProviderCache samlIdentityProviderCache;

    @Override
    public RelyingPartyRegistration findByRegistrationId(@NonNull final String registrationId) {
        return samlIdentityProviderCache.getSamlRelyingPartyRegistrationByRegistrationId(registrationId);
    }
}
