package eu.firmax.cms.auth.security.authenticationConfiguration;

import edu.umd.cs.findbugs.annotations.Nullable;

import java.time.LocalDateTime;

/**
 * Base interface for classes/interfaces which implement a repository for all generic
 * authentication and identity provider configuration information.
 */
public interface AuthenticationConfigurationRepository {

    /**
     * Returns the most recent update date of the group of tables in which authentication related configurations
     * are stored.
     *
     * @return the most recent update date of the group of tables in which authentication related configurations
     * are stored.
     */
    @Nullable
    LocalDateTime getAuthenticationConfigurationLastUpdateTime();
}
