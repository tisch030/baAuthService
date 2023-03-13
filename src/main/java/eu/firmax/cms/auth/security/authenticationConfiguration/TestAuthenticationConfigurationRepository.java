package eu.firmax.cms.auth.security.authenticationConfiguration;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

/**
 * {@link AuthenticationConfigurationRepository} implementation.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Profile("test")
@Primary
public class TestAuthenticationConfigurationRepository implements AuthenticationConfigurationRepository {

    @Nullable
    @Override
    public LocalDateTime getAuthenticationConfigurationLastUpdateTime() {
        return null;
    }
}
