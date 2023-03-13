package eu.firmax.cms.auth.local.log;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.UUID;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.AuthenticationLog.AUTHENTICATION_LOG;

/**
 * {@link AuthenticationLogRepository} implementation which uses JOOQ to store the authentication log in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqAuthenticationLogRepository implements AuthenticationLogRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    public void writeLogEntry(@NonNull AuthenticationOperation authenticationOperation,
                              @Nullable final String personId,
                              @Nullable final String username,
                              @Nullable final String ipAddress) {

        dsl.insertInto(AUTHENTICATION_LOG)
                .set(AUTHENTICATION_LOG.ID, UUID.randomUUID().toString())
                .set(AUTHENTICATION_LOG.AUTHENTICATION_OPERATION, authenticationOperation.name())
                .set(AUTHENTICATION_LOG.PERSON_ID, personId)
                .set(AUTHENTICATION_LOG.USERNAME, username)
                .set(AUTHENTICATION_LOG.IP_ADDRESS, ipAddress)
                .set(AUTHENTICATION_LOG.IP_ADDRESS_ANONYMIZED, false)
                .set(AUTHENTICATION_LOG.CREATED_AT, DSL.currentLocalDateTime())
                .execute();

    }
}
