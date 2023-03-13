package eu.firmax.cms.auth.user;

import edu.umd.cs.findbugs.annotations.Nullable;

import java.io.Serializable;
import java.security.Principal;

/**
 * The base interface used for all {@link Principal}s created by this service.
 * This allows all injections of {@link Principal} to have a common shared set of information
 * independent of the actual authentication method (local, OIDC or SAML).
 */
public interface CustomPrincipal extends Serializable {

    /**
     * Returns the id of the credential object of the user.
     *
     * @return the id of the credential object of the user.
     */
    @Nullable
    String getCredentialId();

    /**
     * Returns the id of the person object of the user.
     *
     * @return the id of the person object of the user.
     */
    @Nullable
    String getPersonId();

    /**
     * Returns the username of the user.
     *
     * @return the username of the user.
     */
    @Nullable
    String getUsername();
}
