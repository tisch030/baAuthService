package eu.firmax.cms.auth.local.log;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * {@link AuthenticationLogRepository} implementation which simply does nothing at all.
 * Needed for tests to avoid a database dependency.
 */
@Profile("test")
@Component
public class TestAuthenticationLogRepository implements AuthenticationLogRepository {

    @Override
    public void writeLogEntry(@NonNull final AuthenticationOperation authenticationOperation,
                              @Nullable final String personId,
                              @Nullable final String username,
                              @Nullable final String ipAddress) {
        // Intentionally left blank.
    }
}
