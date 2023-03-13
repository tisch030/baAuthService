package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProvider;
import eu.firmax.cms.auth.idp.IdentityProviderCache;
import eu.firmax.cms.auth.idp.IdentityProviderType;
import eu.firmax.cms.auth.idp.openid.OidcIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.security.FederatedIdentityConfigurer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service that handles the creation of OpenID Connect {@link ClientRegistration}s.
 * Used to fill the {@link OidcIdentityProviderCache}.
 */
@Component
@RequiredArgsConstructor
public class ClientRegistrationService {

    @NonNull
    private final IdentityProviderCache identityProviderCache;

    @NonNull
    private final OidcIdentityProviderRepository oidcIdentityProviderRepository;

    @NonNull
    private final OidcIdentityProviderEndpointProperties oidcIdentityProviderEndpointProperties;

    /**
     * Creates {@link ClientRegistration}'s for all the {@link IdentityProvider}s that are currently
     * configured by the resource server and use the OIDC standard.
     * The name of the {@link IdentityProvider} will be used as the {@link ClientRegistration} registration id,
     * therefore the created map is {@link ClientRegistration} to the name of the {@link IdentityProvider}.
     *
     * @return a map of created {@link ClientRegistration} to {@link IdentityProvider#name()}, for which the
     * registrations have been created. The name of the identity provider is used as the registration id.
     */
    @NonNull
    public Map<String, ClientRegistration> createClientRegistrations() {
        final List<IdentityProvider> identityProviders = identityProviderCache.getIdentityProviders().stream()
                .filter(identityProvider -> identityProvider.identityProviderType() == IdentityProviderType.OPENID_CONNECT)
                .collect(Collectors.toList());
        return createClientRegistrations(identityProviders);
    }

    /**
     * Creates {@link ClientRegistration}'s for the given {@link IdentityProvider}s, by determining first which
     * of the providers use the OIDC standard and collects the corresponding OIDC specific settings like clientId and
     * clientSecret for that provider.
     * <p>
     * Maps the created {@link ClientRegistration}'s to the {@link IdentityProvider#name()}, for which the registration
     * has been created.
     *
     * @param identityProviders The {@link IdentityProvider}'s for which the client registration should be created.
     * @return a map of created {@link ClientRegistration} to a {@link IdentityProvider#name()}, for which the
     * registrations have been created.
     */
    @NonNull
    private Map<String, ClientRegistration> createClientRegistrations(@NonNull final List<IdentityProvider> identityProviders) {
        if (identityProviders.isEmpty()) {
            return Collections.emptyMap();
        }

        final Set<String> identityProviderIds = identityProviders.stream()
                .map(IdentityProvider::id)
                .collect(Collectors.toSet());

        final Map<String, OidcIdentityProviderRepository.OidcProviderSettings> identityProviderIdToSettings =
                oidcIdentityProviderRepository.loadOidcSettings(identityProviderIds);

        return identityProviders.stream()
                .collect(Collectors.toUnmodifiableMap(
                        IdentityProvider::name,
                        idp -> createOidcIdentityProvider(idp, identityProviderIdToSettings.get(idp.id()))));
    }

    /**
     * Creates a {@link ClientRegistration} for the given {@link IdentityProvider} with the given combination of
     * oidc specific settings. Settings contain information like clientId and clientSecret, which are provided
     * from the provider in order to establish a connection between a client and the provider itself.
     * <p>
     * The id of the registration is set to the name of the identity provider, in order to distinguish the different
     * registration easier.
     *
     * @param identityProvider The {@link IdentityProvider} for which the client registration should be created.
     * @param oidcSettings     The settings which should be used in combination with the given {@link IdentityProvider}.
     * @return a {@link ClientRegistration} which represents the registration of this application with the given OIDC based {@link IdentityProvider}.
     */
    @NonNull
    private ClientRegistration createOidcIdentityProvider(@NonNull final IdentityProvider identityProvider,
                                                          @NonNull final OidcIdentityProviderRepository.OidcProviderSettings oidcSettings) {
        return ClientRegistrations.fromIssuerLocation(oidcSettings.issuerUrl())
                .registrationId(identityProvider.name())
                .clientId(oidcSettings.clientId())
                .clientSecret(oidcSettings.clientSecret())
                .scope(oidcSettings.scopes())
                .redirectUri(FederatedIdentityConfigurer.BASE_URL_VARIABLE + oidcIdentityProviderEndpointProperties.getLoginProcessingEndpoint())
                .build();
    }
}
