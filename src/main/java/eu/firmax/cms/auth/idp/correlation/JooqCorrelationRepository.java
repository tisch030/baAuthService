package eu.firmax.cms.auth.idp.correlation;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.UUID;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.CredentialIdentityProviderCorrelation.CREDENTIAL_IDENTITY_PROVIDER_CORRELATION;

/**
 * {@link CorrelationRepository} implementation which uses JOOQ to access the correlation information
 * in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqCorrelationRepository implements CorrelationRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    public void saveCorrelation(@NonNull final String correlationValue,
                                @NonNull final String credentialsId,
                                @NonNull final String identityProviderId) {

        dsl.insertInto(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION)
                .set(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.ID, UUID.randomUUID().toString())
                .set(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.CORRELATION_VALUE, correlationValue)
                .set(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.CREDENTIAL_ID, credentialsId)
                .set(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.IDENTITY_PROVIDER_ID, identityProviderId)
                .execute();

    }
}
