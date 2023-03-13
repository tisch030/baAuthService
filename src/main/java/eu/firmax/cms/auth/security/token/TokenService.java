package eu.firmax.cms.auth.security.token;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.user.CustomPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;

/**
 * Service for the management of access tokens.
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    @NonNull
    private final TokenRepository tokenRepository;

    /**
     * Deletes all access tokens which have been granted for the person upon a successful logout.
     *
     * @param event event indicating that a person has been logged out.
     */
    @EventListener
    public void logoutSuccess(@NonNull final LogoutSuccessEvent event) {
        if (event.getAuthentication().getPrincipal() instanceof CustomPrincipal principal &&
                principal.getPersonId() != null) {
            final String sessionId = ((WebAuthenticationDetails) event.getAuthentication().getDetails()).getSessionId();
            tokenRepository.deleteAccessTokens(principal.getPersonId(), sessionId);
        }
    }

    /**
     * Saves an access token which is contained inside a {@link OAuth2Authorization}.
     * <p>
     * After a user successfully logged in and optionally acknowledged the consents,
     * a corresponding {@link OAuth2Authorization} will be created, which contains
     * an issued access token and should be saved for future use.
     *
     * @param authorization The authorization from which the information of the access token is extracted from.
     * @throws IllegalArgumentException if the given authorization does not contain an access token.
     */
    public void addAccessTokenToStore(@NonNull final OAuth2Authorization authorization) throws IllegalArgumentException {
        if (authorization.getAccessToken() == null) {
            throw new IllegalArgumentException("The given authorization does not contain an access token.");
        }

        // Add any access token to the repository to keep track of them.
        final Map<String, Object> claims = authorization.getAccessToken().getClaims();
        if (claims == null) {
            // We only use JWT, which have claims.
            throw new UnsupportedOperationException();
        }

        final Authentication authentication = authorization.getAttribute(Principal.class.getName());
        if (authentication == null) {
            // No principal? Impossible.
            throw new UnsupportedOperationException();
        }
        final CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        final WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();

        // Extract some information from the token so that we can display it to the user without the need
        // to decode the token for that. This also allows for nicer sorting and searching.
        final String tokenId = (String) claims.get(JwtClaimNames.JTI);
        final Instant issuedAt = authorization.getAccessToken().getToken().getIssuedAt();
        final Instant expiresAt = authorization.getAccessToken().getToken().getExpiresAt();
        final String tokenValue = authorization.getAccessToken().getToken().getTokenValue();

        final TokenRepository.AccessToken accessToken = new TokenRepository.AccessToken(
                tokenId,
                details.getRemoteAddress(),
                issuedAt,
                expiresAt == null ? Instant.MAX : expiresAt,
                details.getSessionId(),
                tokenValue);

        tokenRepository.addAccessToken(principal.getPersonId(), accessToken);
    }
}
