package eu.firmax.cms.auth.local;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if a user authentication has failed too often and the IP of the user is temporarily banned.
 */
public class BannedIpAuthenticationException extends AuthenticationException {

    public BannedIpAuthenticationException() {
        super("banned");
    }
}
