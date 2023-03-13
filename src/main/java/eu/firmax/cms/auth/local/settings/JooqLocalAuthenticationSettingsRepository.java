package eu.firmax.cms.auth.local.settings;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.LocalAuthenticationSettings.LOCAL_AUTHENTICATION_SETTINGS;

/**
 * {@link LocalAuthenticationSettingsRepository} implementation which uses JOOQ to access the
 * local authentication settings in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqLocalAuthenticationSettingsRepository implements LocalAuthenticationSettingsRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @Nullable
    public LocalAuthenticationBaseSettings loadSettings() {

        final List<AuthenticationSource> authenticationSources = List.of(new AuthenticationSource("test", "database"));

        return dsl.select(
                        LOCAL_AUTHENTICATION_SETTINGS.ID,
                        LOCAL_AUTHENTICATION_SETTINGS.ENABLED,
                        LOCAL_AUTHENTICATION_SETTINGS.MAX_FAILED_ATTEMPTS_PER_USERNAME_AND_IP_IN_ONE_MINUTE)
                .from(LOCAL_AUTHENTICATION_SETTINGS)
                .fetchOne(row -> new LocalAuthenticationBaseSettings(
                        row.get(LOCAL_AUTHENTICATION_SETTINGS.ID),
                        row.get(LOCAL_AUTHENTICATION_SETTINGS.ENABLED),
                        row.get(LOCAL_AUTHENTICATION_SETTINGS.MAX_FAILED_ATTEMPTS_PER_USERNAME_AND_IP_IN_ONE_MINUTE),
                        authenticationSources
                ));
    }
}
