package eu.firmax.cms.auth.idp.correlation;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * {@link CorrelationRepository} implementation which does absolutely nothing.
 * Needed for tests to avoid a database dependency.
 */
@Component
@Profile("test")
@Primary
public class TestCorrelationRepository implements CorrelationRepository {

    @Override
    public void saveCorrelation(@NonNull final String identityProviderId,
                                @NonNull final String credentialId,
                                @NonNull final String correlationValue) {
        // Intentionally left blank.
    }
}
