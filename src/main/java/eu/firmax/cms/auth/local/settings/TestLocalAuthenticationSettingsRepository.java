package eu.firmax.cms.auth.local.settings;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * {@link LocalAuthenticationSettingsRepository} implementation which uses preconfigured local authentication settings.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Primary
@Profile("test")
public class TestLocalAuthenticationSettingsRepository implements LocalAuthenticationSettingsRepository {

    // Authentication base settings
    private static final String AUTHENTICATION_SETTINGS_ID = "TEST_ID";
    private static final boolean ENABLED = true;
    private static final int MAX_FAILED_ATTEMPTS_PER_USERNAME_AND_IP_IN_ONE_MINUTE = 3;

    // Authentication source settings
    private static final String AUTHENTICATION_SOURCE_ID = "TEST_AUTHENTICATION_SOURCE_ID";
    private static final String AUTHENTICATION_SOURCE_NAME = "TEST_AUTHENTICATION_SOURCE_NAME";


    @Override
    @Nullable
    public LocalAuthenticationBaseSettings loadSettings() {

        final List<AuthenticationSource> authenticationSources = List.of(
                new AuthenticationSource(AUTHENTICATION_SOURCE_ID, AUTHENTICATION_SOURCE_NAME)
        );

        return new LocalAuthenticationBaseSettings(
                AUTHENTICATION_SETTINGS_ID,
                ENABLED,
                MAX_FAILED_ATTEMPTS_PER_USERNAME_AND_IP_IN_ONE_MINUTE,
                authenticationSources
        );
    }
}
