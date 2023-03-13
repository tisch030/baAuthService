package eu.firmax.cms.auth.security.authenticationConfiguration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

import static eu.companyx.cms.auth.dto.companyx_backend.CompanyxBackend.COMPANYX_BACKEND;
import static eu.companyx.cms.auth.dto.information_schema.tables.Tables.TABLES;


/**
 * {@link AuthenticationConfigurationRepository} implementation which uses JOOQ to access the generic
 * authentication configuration information in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqAuthenticationConfigurationRepository implements AuthenticationConfigurationRepository {

    @NonNull
    private final DSLContext dsl;

    @Nullable
    @Override
    public LocalDateTime getAuthenticationConfigurationLastUpdateTime() {
        return dsl.select(DSL.max(TABLES.UPDATE_TIME))
                .from(TABLES)
                .where(TABLES.TABLE_SCHEMA.eq(COMPANYX_BACKEND.getName()))
                .fetchOne(row -> row.get(DSL.max(TABLES.UPDATE_TIME)));
    }
}
