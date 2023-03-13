package eu.firmax.cms.auth.local.settings;

import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.security.authenticationConfiguration.AuthenticationConfigurationUpdatedCacheInvalidator;

/**
 * Base interface for classes/interfaces which implement a cache for {@link LocalAuthenticationSettings}.
 */
public interface LocalAuthenticationSettingsCache extends AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Returns the cached {@link LocalAuthenticationSettings}. Null if no settings could be found.
     *
     * @return the cached {@link LocalAuthenticationSettings}. Null if no settings could be found.
     */
    @Nullable
    LocalAuthenticationSettings getLocalAuthenticationSettings();
}
