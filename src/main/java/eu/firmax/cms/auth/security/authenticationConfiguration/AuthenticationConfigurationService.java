package eu.firmax.cms.auth.security.authenticationConfiguration;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;

/**
 * Service that handles generic authentication configuration information.
 * Primarily used to poll the information if the resource server updated the authentication configurations
 * (i.e. activated/deactivated identity providers) and emits a {@link AuthenticationConfigurationUpdatedEvent}
 * that invalides the caches that store the authentication configurations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationConfigurationService {

    private static final int FIXED_DELAY_IN_SECONDS = 5;

    @NonNull
    private final ApplicationEventPublisher eventPublisher;

    @NonNull
    private AuthenticationConfigurationRepository authenticationConfigurationRepository;

    @NonNull
    private OffsetDateTime lastUpdate = OffsetDateTime.now();

    /**
     * Checks periodically if the tables with the identity provider configurations have been updated since we last checked
     * for updates and publishes a {@link AuthenticationConfigurationUpdatedEvent} if that's the case.
     * <p>
     * UPDATE_TIME in INFORMATION_SCHEMA.TABLES contains the time, on which a specific table has been updated.
     * Because UPDATE_TIME saves the time in the UTC-TimeZone, we have to use OffsetDateTime.
     * <p>
     * Furthermore, we have to convert the loaded UPDATE_TIME from LocalDateTime to OffsetDateTime, because
     * JOOQ maps datetime (sql) to LocalDateTime (java).
     * After that we can check if we need to update the identity providers, by comparing our tracked last
     * update time with the loaded update time.
     * <p>
     * ***CAREFULL**** UPDATE_TIME can be null, if for some reason ONLY the database should get restarted, while
     * all other services are still running.
     * If the database needs a restart, all services depending on the database should also get restarted or stopped,
     * in order to avoid side effects with loading/saving.
     * Because the authorization server will also get a restart, it will load the current identity provider
     * configurations correctly.
     * Correctly is worded because of the following case:
     * The authorization server runs and the scheduled check just happened.
     * If for some reason the configurations get updated and the database gets restarted right after the
     * update has been done, the UPDATE_TIME column of INFORMATION_SCHEMA.TABLES will be null.
     * The scheduled check for updates could not get the information that something updated in time and will not
     * update anything, because UPDATE_TIME with the value null indicates no updates.
     * But if the authorization server gets also restarted right after the database restart,
     * it will automatically pick up the correct information at server start.
     */
    @Scheduled(
            timeUnit = TimeUnit.SECONDS,
            fixedDelay = FIXED_DELAY_IN_SECONDS
    )
    public void checkForAuthenticationConfigurationUpdates() {
        boolean publichAuthenticationConfigurationUpdatedEvent = false;
        final LocalDateTime configurationsLastUpdatedAt = authenticationConfigurationRepository.getAuthenticationConfigurationLastUpdateTime();
        if (configurationsLastUpdatedAt != null) {
            final OffsetDateTime configurationsLastUpdated = OffsetDateTime.of(configurationsLastUpdatedAt, ZoneOffset.UTC);
            publichAuthenticationConfigurationUpdatedEvent = configurationsLastUpdated.isAfter(lastUpdate);
        }
        if (publichAuthenticationConfigurationUpdatedEvent) {
            eventPublisher.publishEvent(new AuthenticationConfigurationUpdatedEvent());
            lastUpdate = OffsetDateTime.now();
        }
    }
}
