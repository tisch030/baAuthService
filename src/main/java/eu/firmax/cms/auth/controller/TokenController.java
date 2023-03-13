package eu.firmax.cms.auth.controller;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.token.TokenRepository;
import eu.firmax.cms.auth.user.CustomPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provides endpoints to manage access tokens for authenticated users.
 */
@RestController
@RequiredArgsConstructor
public class TokenController {

    public static final String ACCESS_TOKENS_ENDPOINT = "/api/auth/mytokens";
    public static final String ACCESS_TOKEN_DELETE_ENDPOINT = ACCESS_TOKENS_ENDPOINT + "/{tokenId}";

    private final TokenRepository tokenRepository;

    /**
     * Returns a list of all access tokens which can currently be used to authenticate the user.
     *
     * @param authentication the authentication which identifies the user.
     * @return a list of all access tokens which can currently be used to authenticate the user.
     */
    @GetMapping(ACCESS_TOKENS_ENDPOINT)
    @NonNull
    public ResponseEntity<List<AccessToken>> getAccessTokensOfCurrentUser(@Nullable final Authentication authentication) {

        if (authentication != null && authentication.getPrincipal() instanceof CustomPrincipal principal) {

            final List<AccessToken> accessTokens = tokenRepository.getAccessTokens(principal.getPersonId()).stream()
                    .map(storedToken -> new AccessToken(storedToken.id(), storedToken.issuedTo(), storedToken.issuedOn(), storedToken.expiresAt()))
                    .collect(Collectors.toList());

            return ResponseEntity.ok().body(accessTokens);
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    /**
     * Removes the token with the given id from the tokens which can be used to authenticate the user.
     * The token will be put on a blocklist, thus making it directly unavailable for any further actions.
     *
     * @param tokenId        id of the token which should be removed.
     * @param authentication the authentication which identifies the user.
     * @return nothing.
     */
    @DeleteMapping(ACCESS_TOKEN_DELETE_ENDPOINT)
    public ResponseEntity<Void> deleteAccessToken(@NonNull @PathVariable final String tokenId,
                                                  @Nullable final Authentication authentication) {

        if (authentication != null && authentication.getPrincipal() instanceof CustomPrincipal principal) {
            tokenRepository.deleteAccessToken(principal.getPersonId(), tokenId);
            return ResponseEntity.ok().build();
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    // Do NOT include the actual token in the response, because this WILL cause a security issue with cross site requests.
    // The session id should also stay hidden, although this will not directly lead to any security concerns.
    record AccessToken(@NonNull String id,
                       @Nullable String issuedTo,
                       @Nullable Instant issuedOn,
                       @NonNull Instant expiresAt) {
    }
}
