package eu.firmax.cms.auth.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.SecurityEndpointProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for the creation of {@link RegisteredClient}'s.
 * Used to fill the {@link RegisteredClientCache}.
 */
@Component
@RequiredArgsConstructor
public class RegisteredClientService {

    private static final String REDIRECT_URL_BASE = "http://127.0.0.1:9500";

    @NonNull
    private final RegisteredClientProperties registeredClientProperties;

    @NonNull
    private final SecurityEndpointProperties securityEndpointProperties;

    /**
     * Creates a new {@link RegisteredClient} for each configured client in the {@link RegisteredClientProperties} and
     * returns a lookup map from {@link RegisteredClient} id to the {@link RegisteredClient} instance
     * for faster access times.
     * <p>
     * All created clients share the following OAuth specific configuration:
     * <ul>
     *     <li>Id of the {@link RegisteredClient} object and the clientId will be the same.</li>
     *     <li>Only the "Authorization code flow" is allowed.</li>
     *     <li>Client authentication is done with the PKCE extension instead of a client secret (because we currently only handle public clients).</li>
     *     <li>Redirect url is always the login result endpoint, because we want to make sure that the user maps IDP information with local profiles</li>
     * </ul>
     *
     * @return map from {@link RegisteredClient} id to the {@link RegisteredClient} instance.
     */
    @NonNull
    public Map<String, RegisteredClient> registerClients() {

        return registeredClientProperties.getRegisteredClientInformationList().stream()
                .map(clientInformation -> RegisteredClient.withId(clientInformation.clientId())
                        .clientId(clientInformation.clientId())
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(REDIRECT_URL_BASE + securityEndpointProperties.getLoginResultEndpoint())
                        .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(clientInformation.accessTokenTimeToLive()).build())
                        .build())
                .collect(Collectors.toMap(RegisteredClient::getId, registeredClient -> registeredClient));
    }
}
