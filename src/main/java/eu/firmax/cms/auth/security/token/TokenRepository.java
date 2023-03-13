package eu.firmax.cms.auth.security.token;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.controller.TokenController;

import java.time.Instant;
import java.util.List;

/**
 * Base interface for classes/interfaces which implement a repository for managing {@link AccessToken}s.
 * <p>
 * The tokens can be access by an authenticated user via the endpoints provided by the {@link TokenController}.
 * <p>
 * Additionally used for putting access tokens on a blocklist.
 * Tokens on the blocklist must not be used, even tho their expiration date has not yet been reached.
 */
public interface TokenRepository {

    /**
     * Returns a list of all access tokens which can be used to authenticate the user.
     *
     * @param personId The id of the person for which all issued access tokens will be returned.
     * @return a list of all access tokens which can be used to authenticate the user.
     */
    @NonNull
    List<AccessToken> getAccessTokens(@NonNull final String personId);

    /**
     * Saves the given access token and links it to the given person.
     *
     * @param personId    The id of the person which should be linked with the given access token.
     * @param accessToken The token which will be saved.
     */
    void addAccessToken(@NonNull final String personId,
                        @NonNull final AccessToken accessToken);

    /**
     * Deletes all issued access tokens for the given person and session.
     * Differs from the {@link TokenRepository#deleteAccessTokens(String)} because this method will only delete
     * all tokens of one session, which usually means only one device too.
     *
     * @param personId  The id of the person for which all access tokens should be deleted.
     * @param sessionId The id of the session for which all access tokens should be deleted.
     */
    void deleteAccessTokens(@NonNull final String personId,
                            @NonNull final String sessionId);

    /**
     * Deletes all issued access tokens for the given person.
     * Should be used to log a user out on all devices (e.g. in case the whole account gets locked).
     *
     * @param personId The id of the person for which all access tokens should be deleted.
     */
    void deleteAccessTokens(@NonNull final String personId);

    /**
     * Deletes the given access token and the link between the token and the given person.
     *
     * @param personId The id of the person which is linked with the to be deleted access token.
     * @param tokenId  The token which should be deleted.
     */
    void deleteAccessToken(@NonNull final String personId,
                           @NonNull final String tokenId);

    /**
     * Container which holds information about an access token.
     *
     * @param id        The id of the token.
     * @param issuedTo  The entity for which the token has been issued to.
     * @param issuedOn  The time on which the token has been issued.
     * @param expiresAt The time on which the token expires.
     * @param sessionId The id of the session that was active when the token was created.
     * @param token     The token itself.
     */
    record AccessToken(@NonNull String id,
                       @Nullable String issuedTo,
                       @Nullable Instant issuedOn,
                       @NonNull Instant expiresAt,
                       @NonNull String sessionId,
                       @NonNull String token) {
    }
}
