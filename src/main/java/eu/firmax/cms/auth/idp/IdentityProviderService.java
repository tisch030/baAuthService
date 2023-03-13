package eu.firmax.cms.auth.idp;


import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.openid.OidcIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderEndpointProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Handles identity providers information.
 */
@Service
@RequiredArgsConstructor
public class IdentityProviderService {

    @NonNull
    private final SamlIdentityProviderEndpointProperties samlIdentityProviderEndpointProperties;

    @NonNull
    private final OidcIdentityProviderEndpointProperties oidcIdentityProviderEndpointProperties;

    @NonNull
    private final IdentityProviderCache identityProviderCache;

    /**
     * Returns an optional {@link IdentityProviderAndUniqueIdentifierMappingAttribute} which maps the id of an identity provider
     * to the configured unique identifier attribute, by which a user at an identity provider can be uniquely identified.
     * The lookup is made with the given identity provider name.
     * If no mapping attribute is configured, an empty optional is returned.
     *
     * @param identityProviderName name of the identity provider for which the mapping attribute will be returned.
     * @return an optional {@link IdentityProviderAndUniqueIdentifierMappingAttribute} or an empty optional, if no
     * unique identifier could be found for the given identity provider name.
     */
    @NonNull
    public Optional<IdentityProviderAndUniqueIdentifierMappingAttribute> getIdentityProviderUniqueIdentifierMappingAttribute(@NonNull final String identityProviderName) {
        final IdentityProvider identityProvider = identityProviderCache.getIdentityProviders().stream()
                .filter(idp -> idp.name().equals(identityProviderName))
                .findAny()
                .orElse(null);

        if (identityProvider == null) {
            return Optional.empty();
        }

        return Optional.of(new IdentityProviderAndUniqueIdentifierMappingAttribute(identityProvider.id(), identityProvider.uniqueIdentifierAttribute()));
    }

    /**
     * Returns the URL of an identity provider if only exactly one identity provider is currently active, returns null otherwise.
     *
     * @return the URL of an identity provider if only exactly one identity provider is currently active. Otherwise, returns null.
     */
    @Nullable
    public String getIdentityProviderUrlIfUnambiguous(@NonNull final HttpServletRequest request) {

        final List<IdentityProvider> identityProviders = identityProviderCache.getIdentityProviders();
        if (identityProviders.size() != 1) {
            return null;
        }

        final IdentityProvider identityProvider = identityProviders.iterator().next();
        final String urlPath = identityProvider.identityProviderType() == IdentityProviderType.SAML ?
                samlIdentityProviderEndpointProperties.getLoginInitiateEndpoint() :
                (oidcIdentityProviderEndpointProperties.getLoginInitiateEndpoint() + "/{idpName}");

        return UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
                .replaceQuery(null)
                .replacePath(urlPath)
                .buildAndExpand(identityProvider.name())
                .toUriString();
    }

    /**
     * Returns a list of identity provider information that are useful for displaying on the login page.
     *
     * @return a list of identity provider information that are useful for displaying on the login page.
     */
    @NonNull
    public List<LoginPageIdentityProvider> getIdentityProviderForLoginPageOverview() {
        return identityProviderCache.getIdentityProviders().stream()
                .map(identityProvider -> new LoginPageIdentityProvider(
                        identityProvider.name(),
                        identityProvider.buttonLabel(),
                        identityProvider.identityProviderType() == IdentityProviderType.SAML ?
                                (samlIdentityProviderEndpointProperties.getLoginInitiateEndpoint().replace("{idpName}", identityProvider.name())) :
                                (oidcIdentityProviderEndpointProperties.getLoginInitiateEndpoint() + "/" + identityProvider.name())))
                .collect(Collectors.toList());
    }

    record LoginPageIdentityProvider(@NonNull String name,
                                     @NonNull String buttonLabel,
                                     @NonNull String authenticationUrl) {
    }

    public record IdentityProviderAndUniqueIdentifierMappingAttribute(@NonNull String identityProviderId,
                                                                      @Nullable String mappingAttribute) {
    }

}
