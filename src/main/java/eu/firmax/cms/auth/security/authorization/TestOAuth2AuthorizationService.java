package eu.firmax.cms.auth.security.authorization;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.security.token.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

/**
 * {@link OAuth2AuthorizationService} implementation which uses the {@link InMemoryOAuth2AuthorizationService}
 * for the management of {@link OAuth2Authorization}s.
 * Needed for tests to avoid a redis dependency.
 */
@Service
@Primary
@Profile("test")
@RequiredArgsConstructor
public class TestOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();

    private final TokenService tokenService;

    @Override
    public void save(@NonNull final OAuth2Authorization authorization) {
        authorizationService.save(authorization);
        if (authorization.getAccessToken() != null) {
            tokenService.addAccessTokenToStore(authorization);
        }
    }

    @Override
    public void remove(@NonNull final OAuth2Authorization authorization) {
        authorizationService.remove(authorization);
    }

    @Override
    @Nullable
    public OAuth2Authorization findById(@NonNull final String id) {
        return authorizationService.findById(id);
    }

    @Override
    @Nullable
    public OAuth2Authorization findByToken(@NonNull final String token,
                                           @Nullable final OAuth2TokenType tokenType) {
        return authorizationService.findByToken(token, tokenType);
    }
}
