package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.IdentityProvider;
import eu.firmax.cms.auth.idp.saml.bundid.StorkQaaLevel;

import java.util.Map;
import java.util.Set;

/**
 * Base interface for classes/interfaces that implement a repository for {@link IdentityProvider} SAML settings.
 */
public interface SamlIdentityProviderRepository {


    /**
     * Returns a map of the given identity provider ids to their SAML specific settings.
     * If an identity provider is not of the type SAML, it will not be included in the resulting map.
     *
     * @param identityProviderIds The identity provider ids for which their SAML specific settings are returned.
     * @return a map of the given identity provider ids to their SAML specific settings.
     */
    @NonNull
    Map<String, SamlProviderSettings> loadSamlSettings(@NonNull final Set<String> identityProviderIds);


    /**
     * Returns a map of all SAML identity provider names to their SAML specific settings.
     * If an identity provider is not of the type SAML, it will not be included in the resulting map.
     *
     * @return a map of all SAML identity provider names to their SAML specific settings.
     */
    @NonNull
    Map<String, SamlProviderSettings> loadAllSamlSettingsMappedByIdentityProviderName();

    record SamlProviderSettings(@NonNull String issuerUrl,
                                @Nullable StorkQaaLevel storkQaaLevel) {
    }
}
