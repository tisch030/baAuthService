package eu.firmax.cms.auth.local;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.local.database.DatabaseAuthenticationService;
import eu.firmax.cms.auth.local.log.AuthenticationLogService;
import eu.firmax.cms.auth.local.ratelimiting.LoginAttemptService;
import eu.firmax.cms.auth.user.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

/**
 * Implementation of the Spring {@link AuthenticationProvider} interface, which is used to authenticate a user.
 * This authentication provider handles {@link UsernamePasswordAuthenticationToken}s, i.e. authentication via
 * the login form.
 * The actual authentication is delegated to an other implementations of the {@link AuthenticationProvider} interface,
 * which is loaded from the {@link LocalAuthenticationProviderCache}.
 * We do this because we want to extend the DAOAuthenticationProvider for authentication against a database, but without rewriting it.
 * The cache is filled by the {@link DatabaseAuthenticationService} with a provider which loads users from the database.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LocalAuthenticationProvider implements AuthenticationProvider {

    @NonNull
    private final LocalAuthenticationProviderCache localAuthenticationProviderCache;

    @NonNull
    private final LoginAttemptService loginAttemptService;

    @NonNull
    private final AuthenticationLogService authenticationLogService;

    @Override
    public Authentication authenticate(@NonNull final Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            log.error("We only support UsernamePasswordAuthenticationToken and told spring so, this is an indication of a bug.");
            return null;
        }

        // Make some pre checks like making sure a password and username has been provided.
        if (authentication.getCredentials() == null || authentication.getCredentials().toString().isEmpty()) {
            throw new BadCredentialsException("Credentials must be set.");
        }

        final String username = (String) authentication.getPrincipal();

        // Check if the user has exceeded the maximum number of login tries.
        if (loginAttemptService.isBlocked(username)) {
            loginAttemptService.loginBlocked(username);
            throw new BannedIpAuthenticationException();
        }

        try {
            // Authenticate the user.
            final Authentication authenticationResult = this.doAuthenticate(authentication);
            if (authenticationResult == null) {
                // We were not able to perform a login, but it also didn't fail.
                return null;
            }

            // Make sure the authenticated user got a valid principal.
            final CustomUserDetails principal = (CustomUserDetails) authenticationResult.getPrincipal();
            if (principal.getCredentialId() == null) {
                throw new UnsupportedOperationException("Authenticated principal does not have credentials. This should never happen if the local authentication provider has been used.");
            }

            // Remove any failed login attempts from the cache.
            loginAttemptService.loginSuccessful(username);

            return authenticationResult;
        } catch (final LockedException | DisabledException | BadCredentialsException e) {
            loginAttemptService.loginFailed(username);
            throw e;
        }
    }

    /**
     * Performs the actual authentication with the active local authentication provider retrieved from the cache.
     * Returns null if the provider could not perform the authentication, either due to a technical error
     * or because the provider was not applicable for the authentication type (shouldn't really happen).
     *
     * @param authentication the authentication which should be validated by the authentication providers.
     * @return the Authentication of a user or null.
     * @throws BadCredentialsException if the user was not found by any provider or the password didn't match.
     * @throws DisabledException       if the user was found by at least one provider but is disabled.
     * @throws LockedException         if the user was found by at least one provider but is locked.
     */
    @Nullable
    private Authentication doAuthenticate(@NonNull final Authentication authentication) {

        final AuthenticationProvider authenticationProvider = localAuthenticationProviderCache.getLocalAuthenticationProvider();

        if (authenticationProvider == null) {
            return null;
        }

        try {
            final Authentication result = authenticationProvider.authenticate(authentication);
            if (result != null) {
                return result;
            }
        } catch (final DisabledException | LockedException e) {
            // Found the user but the account is not active. We don't want to recover from this.
            throw e;
        } catch (@NonNull final BadCredentialsException e) {
            // User did not provide correct credentials.
            throw new BadCredentialsException("Bad credentials");
        } catch (@NonNull final RuntimeException e) {
            // We will ignore this result completely but log it. Something may be broken.
            log.warn("Exception during authentication.", e);
            e.printStackTrace();
            final WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
            authenticationLogService.authenticationError((String) authentication.getPrincipal(), details.getRemoteAddress());
        }

        // Should not happen, because we handle the cases above.
        return null;
    }

    @Override
    public boolean supports(@NonNull final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
