package eu.firmax.cms.auth.local.ratelimiting;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Base interface for classes/interfaces which implement a cache for limiting username/password login attempts.
 * Does not track login attempts at the identity providers, as they hopefully have their own rate limiting mechanism.
 * <p>
 * For how long login attempts are tracked depends on the specific implementation of the cache.
 */
public interface LoginAttemptCache {

    /**
     * Returns the number of login attempts for the given username, executed by the given ip.
     *
     * @param username The username which has been used for the login attempts.
     * @param ip       The ip address from which the login attempts originated.
     * @return number of login attempts.
     */
    int getNumberOfLoginAttempts(@NonNull final String username,
                                 @NonNull final String ip);

    /**
     * Increases the number of login attempts for the given username, executed by the given ip, by exactly one.
     *
     * @param username The username which has been used for the login attempts.
     * @param ip       The ip address from which the login attempts originated.
     */
    void increaseLoginAttemptsByOne(@NonNull final String username,
                                    @NonNull final String ip);

    /**
     * Clears the login attempts for the given username, executed by the given ip.
     *
     * @param username The username which has been used for the login attempts.
     * @param ip       The ip address from which the login attempts originated.
     */
    void clearLoginAttempts(@NonNull final String username,
                            @NonNull final String ip);

}
