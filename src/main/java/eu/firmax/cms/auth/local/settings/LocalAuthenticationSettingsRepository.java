package eu.firmax.cms.auth.local.settings;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

import java.util.List;

/**
 * Base interface for classes/interfaces which implement a repository for {@link LocalAuthenticationBaseSettings}.
 * The base settings among other things includes the password settings,
 * which authentication sources are provided and roles for which one can register for.
 */
public interface LocalAuthenticationSettingsRepository {

    /**
     * Returns {@link LocalAuthenticationBaseSettings}. Null if no settings have been found.
     *
     * @return {@link LocalAuthenticationBaseSettings}. Null if no settings have been found.
     */
    @Nullable
    LocalAuthenticationBaseSettings loadSettings();

    /**
     * Container which contains base local (e.g. username/password) authentication settings information.
     *
     * @param id                                           The id of the settings object.
     * @param enabled                                      States whether the local authentication is enabled or not.
     * @param maxFailedAttemptsPerUsernameAndIpInOneMinute How many login attempts are allowed.
     * @param authenticationSources                        The authentication sources which should be used for the authentication.
     */
    record LocalAuthenticationBaseSettings(@NonNull String id,
                                           boolean enabled,
                                           int maxFailedAttemptsPerUsernameAndIpInOneMinute,
                                           @NonNull List<AuthenticationSource> authenticationSources) {
    }

    record AuthenticationSource(@NonNull String id,
                                @NonNull String name) {
    }

}
