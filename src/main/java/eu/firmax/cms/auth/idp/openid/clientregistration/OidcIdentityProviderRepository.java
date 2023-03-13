package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.IdentityProvider;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Base interface for classes/interfaces that implement a repository for {@link IdentityProvider}
 * OpenID Connect settings.
 */
public interface OidcIdentityProviderRepository {

    /**
     * Returns a map of the given identity provider ids to their OIDC specific settings.
     * If an identity provider is not of the type OIDC, it will not be included in the resulting map.
     *
     * @param identityProviderIds The identity provider ids for which their OIDC specific settings are returned.
     * @return a map of the given identity provider ids to their OIDC specific settings.
     */
    @NonNull
    Map<String, OidcProviderSettings> loadOidcSettings(@NonNull final Set<String> identityProviderIds);

    record OidcProviderSettings(boolean useDiscovery,
                                @Nullable String issuerUrl,
                                @Nullable String authorizationUrl,
                                @Nullable String jwksUrl,
                                @Nullable String userInfoUrl,
                                @Nullable String tokenUrl,
                                @NonNull String clientId,
                                @NonNull String clientSecret,
                                @Nullable Collection<String> scopes) {
    }
}
