package eu.firmax.cms.auth.local.database;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.user.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Optional;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.Credential.CREDENTIAL;
import static eu.companyx.cms.auth.dto.companyx_backend.tables.CredentialIdentityProviderCorrelation.CREDENTIAL_IDENTITY_PROVIDER_CORRELATION;
import static eu.companyx.cms.auth.dto.companyx_backend.tables.Person.PERSON;

/**
 * {@link UserDetailsRepository} implementation which uses JOOQ to access the user details in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqUserDetailsRepository implements UserDetailsRepository {

    @NonNull
    private final DSLContext dsl;

    /**
     * Retrieves the {@link CustomUserDetails} of a user based on the username or an empty optional
     * if no user with the given username could be found. The lookup is not case-sensitive.
     *
     * @param username The username identifying the user whose data should be retrieved.
     * @return the {@link CustomUserDetails} of a user based on the username. Or an empty optional
     * if no user with the given username could be found.
     */
    @Override
    @NonNull
    public Optional<CustomUserDetails> lookupUserByUsername(@NonNull final String username) {
        return dsl.select(
                        CREDENTIAL.ID,
                        CREDENTIAL.USERNAME,
                        CREDENTIAL.PASSWORD,
                        CREDENTIAL.LOCKED,
                        CREDENTIAL.PASSWORD_EXPIRED,
                        CREDENTIAL.SCHEDULED_LOCKING_DATE,
                        PERSON.ID)
                .from(CREDENTIAL)
                .innerJoin(PERSON).on(PERSON.CREDENTIAL_ID.eq(CREDENTIAL.ID))
                .where(CREDENTIAL.USERNAME.equalIgnoreCase(username))
                .fetchOptional(row -> new CustomUserDetails(
                        row.get(CREDENTIAL.USERNAME),
                        row.get(CREDENTIAL.PASSWORD),
                        !row.get(CREDENTIAL.LOCKED),
                        !row.get(CREDENTIAL.PASSWORD_EXPIRED),
                        row.get(PERSON.ID),
                        row.get(CREDENTIAL.ID)));
    }

    @Override
    @NonNull
    public Optional<CustomUserDetails> lookupUserByIdentityProviderMapping(@NonNull final String identityProviderId,
                                                                           @NonNull final String mappingAttributeValue) {
        return dsl.select(
                        CREDENTIAL.ID,
                        CREDENTIAL.USERNAME,
                        CREDENTIAL.PASSWORD,
                        CREDENTIAL.LOCKED,
                        CREDENTIAL.PASSWORD_EXPIRED,
                        CREDENTIAL.SCHEDULED_LOCKING_DATE,
                        PERSON.ID)
                .from(CREDENTIAL)
                .innerJoin(PERSON).on(PERSON.CREDENTIAL_ID.eq(CREDENTIAL.ID))
                .innerJoin(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION).on(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.CREDENTIAL_ID.eq(CREDENTIAL.ID))
                .where(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.IDENTITY_PROVIDER_ID.eq(identityProviderId)
                        .and(CREDENTIAL_IDENTITY_PROVIDER_CORRELATION.CORRELATION_VALUE.eq(mappingAttributeValue)))
                .fetchOptional(row -> new CustomUserDetails(
                        row.get(CREDENTIAL.USERNAME),
                        row.get(CREDENTIAL.PASSWORD),
                        !row.get(CREDENTIAL.LOCKED),
                        !row.get(CREDENTIAL.PASSWORD_EXPIRED),
                        row.get(PERSON.ID),
                        row.get(CREDENTIAL.ID)));
    }
}
