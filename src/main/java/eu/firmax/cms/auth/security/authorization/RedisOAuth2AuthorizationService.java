package eu.firmax.cms.auth.security.authorization;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.token.TokenService;
import eu.firmax.cms.auth.util.GenericRedisSerializer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.stereotype.Service;

/**
 * {@link OAuth2AuthorizationService} implementation which uses redis for the management of {@link OAuth2Authorization}s.
 * <p>
 * "initialized" (uncompleted) authorizations are authorizations for which an access token has not yet been granted.
 * This state occurs with the authorization_code grant flow during the user consent step OR
 * when the code is returned in the authorization response but the access token request has not yet been initiated.
 * <p>
 * We only save uncompleted authorizations, because completed authorization contain only the access tokens and these
 * access tokens are managed by our {@link TokenService}.
 * Also, we don't support any of the use cases, where retrieving an authorization is needed to be based upon an access token,
 * refresh token or state, only if an authorization code is used to retrieve the authorization.
 * The following use cases would require saving "completed" authorizations:
 * <ul>
 *     <li>Display of consents (state is used as token type)</li>
 *     <li>Dynamic client registration with {@link OidcClientRegistrationAuthenticationProvider}</li>
 *     <li>Dynamic client configuration with {@link OidcClientConfigurationAuthenticationProvider}</li>
 *     <li>User-Info-Endpoint with {@link OidcUserInfoAuthenticationProvider}</li>
 *     <li>Token revokation with {@link OAuth2TokenRevocationAuthenticationProvider} </li>
 *     <li>Token introspection with {@link OAuth2TokenIntrospectionAuthenticationProvider} </li>
 *     <li>Refresh token usage with {@link OAuth2RefreshTokenAuthenticationProvider} </li>
 * </ul>
 */
@Service
@ConditionalOnClass(RedisConnectionFactory.class)
@Profile("default")
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String AUTHORIZATION_PREFIX = "cc:auth:authorization:";

    @NonNull
    private final TokenService tokenService;

    @NonNull
    private final RedisTemplate<String, OAuth2Authorization> initializedAuthorizationsRedisTemplate;


    public RedisOAuth2AuthorizationService(@NonNull final RedisConnectionFactory redisConnectionFactory,
                                           @NonNull final TokenService tokenService) {
        this.initializedAuthorizationsRedisTemplate = new RedisTemplate<>();
        this.initializedAuthorizationsRedisTemplate.setKeySerializer(new StringRedisSerializer());
        this.initializedAuthorizationsRedisTemplate.setValueSerializer(new GenericRedisSerializer<>());
        this.initializedAuthorizationsRedisTemplate.setConnectionFactory(redisConnectionFactory);
        this.initializedAuthorizationsRedisTemplate.afterPropertiesSet();

        this.tokenService = tokenService;
    }

    @Override
    public void save(@NonNull final OAuth2Authorization authorization) {
        if (authorization.getAccessToken() == null) {
            // Uncompleted authorizations. Store for future use.
            initializedAuthorizationsRedisTemplate.opsForValue().set(AUTHORIZATION_PREFIX + getAuthorizationId(authorization), authorization);
        } else {
            tokenService.addAccessTokenToStore(authorization);
        }
    }

    @Override
    public void remove(@NonNull final OAuth2Authorization authorization) {
        if (authorization.getAccessToken() == null) {
            initializedAuthorizationsRedisTemplate.delete(AUTHORIZATION_PREFIX + getAuthorizationId(authorization));
        }
    }

    @Override
    @NonNull
    public OAuth2Authorization findById(@NonNull final String authorizationId) {
        throw new UnsupportedOperationException();
    }

    @Override
    @Nullable
    public OAuth2Authorization findByToken(@NonNull final String token,
                                           @Nullable final OAuth2TokenType tokenType) {
        return initializedAuthorizationsRedisTemplate.opsForValue().get(AUTHORIZATION_PREFIX + token);
    }

    @NonNull
    private String getAuthorizationId(@NonNull final OAuth2Authorization authorization) {
        final OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (authorizationCode != null) {
            return authorizationCode.getToken().getTokenValue();
        }

        final Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state != null) {
            return (String) state;
        }

        throw new UnsupportedOperationException("Unsupported token type");
    }
}
