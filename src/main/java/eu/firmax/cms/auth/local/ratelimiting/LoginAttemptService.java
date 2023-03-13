package eu.firmax.cms.auth.local.ratelimiting;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettings;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsCache;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service to prevent brute force authentication attempts ("password guessing").
 * <p>
 * This service is notified about all successful and failed login attempts and will put username + IP combinations
 * on a temporary ban list if too many failed login attempts are tried in succession.
 * The authentication providers can check if a username is currently on the ban list for IP that tries to authenticate.
 * <p>
 * The IP ban is username specific, because otherwise shared IP addresses might lead to blocked authentication requests,
 * even though the user never tried to log in before.
 * Shared IP addresses are quite common with IPv6 light nowadays or users in the same household.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    @NonNull
    private final LocalAuthenticationSettingsCache localAuthenticationSettingsCache;

    /**
     * Maps username + IP (cache key) to the number of failed login attempts in the last minute.
     * If no entry exists in this cache no failed login attempts have been made in the last minute.
     * Cache entries expire one minute after the last modification.
     * Therefor a user has to wait at least one minute after a temporary ban to try again, otherwise the cache
     * entry will not expire and the user has to wait another full minute.
     */
    @NonNull
    private final LoginAttemptCache failedLoginAttemptsCache;

    /**
     * Contains the original request of the client. Used to determine the IP address of the client.
     */
    @NonNull
    private final HttpServletRequest request;

    /**
     * Returns the currently configured amount of tries per minute a user is allowed to have.
     *
     * @return the currently configured amount of tries per minute a user is allowed to have.
     */
    public int getMaxFailedAttemptsPerUsernameAndIpInOneMinute() {
        final LocalAuthenticationSettings settings = localAuthenticationSettingsCache.getLocalAuthenticationSettings();
        return settings == null ? 0 : settings.maxFailedAttemptsPerUsernameAndIpInOneMinute();
    }

    /**
     * Returns true if too many failed authentication attempts were tried for this username by the requesters IP in the last minute. False otherwise.
     *
     * @param username username that should be checked (for which the authentication attempt is made).
     * @return true if too many failed authentication attempts were tried for this username by the requesters IP in the last minute. False otherwise.
     */
    public boolean isBlocked(@NonNull final String username) {
        return getNumberOfFailedAttempts(username) >= getMaxFailedAttemptsPerUsernameAndIpInOneMinute();
    }

    /**
     * Must be called whenever an authentication attempt was blocked for a user.
     * The failed authentication attempt counter is left unchanged.
     *
     * @param username username for which the login was blocked.
     */
    public void loginBlocked(@NonNull final String username) {
        log.debug("Login blocked for {} with IP {}.", username, request.getRemoteAddr());
    }

    /**
     * Must be called whenever an authentication attempt was successful for a user.
     * The failed authentication attempt counter is reset for this username and the requesters IP.
     *
     * @param username username for which the login was successful.
     */
    public void loginSuccessful(@NonNull final String username) {
        failedLoginAttemptsCache.clearLoginAttempts(username, request.getRemoteAddr());
        log.debug("Successful login for {} with IP {}.", username, request.getRemoteAddr());
    }

    /**
     * Must be called whenever an authentication attempt failed for a user.
     * The failed authentication attempt counter is incremented by one for this username and the requesters IP.
     *
     * @param username username for which the login failed.
     */
    public void loginFailed(@NonNull final String username) {
        failedLoginAttemptsCache.increaseLoginAttemptsByOne(username, request.getRemoteAddr());
        log.debug("Failed login for {} with IP {}.", username, request.getRemoteAddr());
    }

    /**
     * Returns the number of failed login attempts in the last minute for this username and the requesters IP.
     *
     * @param username username for which the number of failed login attempts is returned.
     * @return the number of failed login attempts in the last minute for this username and the requesters IP.
     */
    private int getNumberOfFailedAttempts(@NonNull final String username) {
        return failedLoginAttemptsCache.getNumberOfLoginAttempts(username, request.getRemoteAddr());
    }
}
