package eu.firmax.cms.auth.idp.saml.samlsettings;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.relyingpartyregistration.SamlIdentityProviderRepository;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

/**
 * Base interface for classes/interfaces which implement a cache for {@link SamlIdentityProviderRepository.SamlProviderSettings}.
 * Mainly used to cache the configured extensions for each SAML provider.
 */
public interface SamlSettingsCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the {@link SamlIdentityProviderRepository.SamlProviderSettings} of the given SAML identity provider.
     *
     * @param samlIdentityProviderId The id of the saml identity provider, from which one wants the saml settings.
     * @return the {@link SamlIdentityProviderRepository.SamlProviderSettings} of the given saml identity provider.
     */
    @NonNull
    SamlIdentityProviderRepository.SamlProviderSettings getSamlProviderSettings(@NonNull final String samlIdentityProviderId);
}
