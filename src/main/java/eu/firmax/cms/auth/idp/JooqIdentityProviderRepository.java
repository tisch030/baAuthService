package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Objects;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.IdentityProvider.IDENTITY_PROVIDER;

/**
 * {@link IdentityProviderRepository} implementation which uses JOOQ to access the identity provider information
 * in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqIdentityProviderRepository implements IdentityProviderRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @NonNull
    public List<IdentityProvider> loadEnabledIdentityProvidersOrderedByPriority() {

        return dsl.select(
                        IDENTITY_PROVIDER.ID,
                        IDENTITY_PROVIDER.NAME,
                        IDENTITY_PROVIDER.ENABLED,
                        IDENTITY_PROVIDER.POSITION,
                        IDENTITY_PROVIDER.BUTTON_LABEL,
                        IDENTITY_PROVIDER.IDENTITY_PROVIDER_TYPE,
                        IDENTITY_PROVIDER.UNIQUE_IDENTIFIER_ATTRIBUTE_AT_IDP)
                .from(IDENTITY_PROVIDER)
                .where(IDENTITY_PROVIDER.ENABLED.eq(true))
                .orderBy(IDENTITY_PROVIDER.POSITION.asc())
                .fetch(row -> new IdentityProvider(
                        row.get(IDENTITY_PROVIDER.ID),
                        row.get(IDENTITY_PROVIDER.NAME),
                        row.get(IDENTITY_PROVIDER.ENABLED),
                        row.get(IDENTITY_PROVIDER.POSITION),
                        row.get(IDENTITY_PROVIDER.BUTTON_LABEL),
                        IdentityProviderType.valueOf(row.get(IDENTITY_PROVIDER.IDENTITY_PROVIDER_TYPE)),
                        row.get(IDENTITY_PROVIDER.UNIQUE_IDENTIFIER_ATTRIBUTE_AT_IDP)));
    }

    @NonNull
    public String loadIdentityProviderId(@NonNull final String identityProviderName) {

        return Objects.requireNonNull(dsl.select(IDENTITY_PROVIDER.ID)
                .from(IDENTITY_PROVIDER)
                .where(IDENTITY_PROVIDER.ENABLED.eq(true))
                .and(IDENTITY_PROVIDER.NAME.eq(identityProviderName))
                .fetchOne(row -> row.get(IDENTITY_PROVIDER.ID)));

    }
}
