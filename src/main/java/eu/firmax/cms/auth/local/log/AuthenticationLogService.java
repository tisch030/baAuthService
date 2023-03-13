package eu.firmax.cms.auth.local.log;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.user.CustomPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import java.security.Principal;

/**
 * Service that handles the logging of authentication operations like failed/succeeded authentication tries.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationLogService {

    @NonNull
    private final AuthenticationLogRepository authenticationLogRepository;

    /**
     * Listener for the event {@link AbstractAuthenticationFailureEvent} and logs that a failed authentication
     * attempt occurred.
     *
     * @param event The event which indicates a failed authentication attempt.
     */
    @EventListener
    public void authenticationFailed(@NonNull final AbstractAuthenticationFailureEvent event) {
        final String username;
        if (event.getAuthentication().getPrincipal() instanceof String principal) {
            username = principal;
        } else if (event.getAuthentication().getPrincipal() instanceof UsernamePasswordAuthenticationToken principal) {
            username = principal.getName();
        } else {
            username = "UNKNOWN";
        }
        final WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) event.getAuthentication().getDetails();
        this.authenticationFailed(username, authenticationDetails == null ? null : authenticationDetails.getRemoteAddress());
    }


    /**
     * Listener for the event {@link AuthenticationSuccessEvent} and logs that a succeeded authentication
     * attempt occurred.
     *
     * @param event The event which indicates a succeeded authentication attempt.
     * @throws InternalAuthenticationServiceException if the {@link Principal} of the {@link Authentication} does
     *                                                not conform to one of the implementations of {@link CustomPrincipal}. Indicates more or less an error in the
     *                                                authorization server itself, because there has been somehow a successful authentication that is neither done
     *                                                by OIDC, SAML nor username/password.
     */
    @EventListener
    public void authenticationSuccess(@NonNull final AuthenticationSuccessEvent event) throws InternalAuthenticationServiceException {
        if (event.getAuthentication() instanceof OAuth2AuthorizationCodeRequestAuthenticationToken ||
                event.getAuthentication() instanceof OAuth2ClientAuthenticationToken ||
                event.getAuthentication() instanceof OAuth2AccessTokenAuthenticationToken) {
            return;
        }

        if (event.getAuthentication().getPrincipal() instanceof CustomPrincipal principal) {
            final WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) event.getAuthentication().getDetails();
            this.login(principal, authenticationDetails.getRemoteAddress());
            return;
        }
        throw new InternalAuthenticationServiceException("Principal has wrong format");
    }

    /**
     * Listener for the Event {@link LogoutSuccessEvent} and logs that user has logged out successfully.
     *
     * @param event The event which indicates a succeeded logout.
     * @throws InternalAuthenticationServiceException if the {@link Principal} of the {@link Authentication} does
     *                                                not conform to one of the implementations of {@link CustomPrincipal}. Indicates more or less an error in the
     *                                                authorization server itself, because there has been somehow a successful logout from a user,
     *                                                that has been previously neither authenticated by OIDC, SAML nor by username/password.
     */
    @EventListener
    public void logoutSuccess(@NonNull final LogoutSuccessEvent event) throws InternalAuthenticationServiceException {
        if (event.getAuthentication().getPrincipal() instanceof CustomPrincipal principal) {
            final WebAuthenticationDetails authenticationDetails = (WebAuthenticationDetails) event.getAuthentication().getDetails();
            this.logout(principal, authenticationDetails.getRemoteAddress());
            return;
        }
        throw new InternalAuthenticationServiceException("Principal has wrong format");
    }

    /**
     * Creates a new log entry for the user that has successfully logged in.
     *
     * @param principal The login user details of the user.
     */
    private void login(@NonNull final CustomPrincipal principal,
                       @Nullable final String ipAddress) {
        this.log(AuthenticationOperation.LOGIN, principal.getUsername(), principal.getPersonId(), principal.getCredentialId(), ipAddress);
    }

    /**
     * Creates a new log entry for the user that has successfully logged out.
     */
    private void logout(@NonNull final CustomPrincipal principal,
                        @Nullable final String ipAddress) {
        this.log(AuthenticationOperation.LOGOUT, principal.getUsername(), principal.getPersonId(), principal.getCredentialId(), ipAddress);
    }

    /**
     * Creates a new log entry for the username that's authentication has failed.
     *
     * @param username The username of the user that tried to log in.
     */
    private void authenticationFailed(@NonNull final String username,
                                      @Nullable final String ipAddress) {
        this.log(AuthenticationOperation.AUTHENTICATION_FAILED, username, null, null, ipAddress);
    }

    /**
     * Creates a new log entry for the username that's login produced a server side error.
     *
     * @param username The username of the user that tried to log in.
     */
    public void authenticationError(@NonNull final String username,
                                    @Nullable final String ipAddress) {
        this.log(AuthenticationOperation.AUTHENTICATION_ERROR, username, null, null, ipAddress);
    }

    /**
     * Creates a new log entry within the authentication log with the given operation.
     *
     * @param authenticationOperation The {@link AuthenticationOperation} that has been performed.
     * @param username                The username that has been used log.
     * @param personId                The id of the person the log entry is made for.
     * @param credentialId            The id of the credential the log entry is made for.
     * @param ipAddress               The IP address of the user who tried to log in.
     */
    private void log(@NonNull final AuthenticationOperation authenticationOperation,
                     @Nullable final String username,
                     @Nullable final String personId,
                     @Nullable final String credentialId,
                     @Nullable final String ipAddress) {
        authenticationLogRepository.writeLogEntry(authenticationOperation, personId, username, ipAddress);
        log.info("{}: {} {} {}", authenticationOperation, username, personId, credentialId);
    }

}
