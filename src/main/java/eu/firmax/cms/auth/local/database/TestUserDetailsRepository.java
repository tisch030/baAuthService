package eu.firmax.cms.auth.local.database;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.user.CustomUserDetails;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * {@link UserDetailsRepository} implementation which uses preconfigured user details.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Profile("test")
@Primary
public class TestUserDetailsRepository implements UserDetailsRepository {

    public static final String USERNAME = "testUser";
    public static final String PASSWORD_RAW = "testPassword"; // Equals to the hashed BCRYPT value.
    private static final String PASSWORD_BCRYPT_HASHED = "$2y$10$4CaqzHilQMP/EMpW6WH0QOJPMeyeRCiQsnzkzX224yrkEVUvJMwWa";
    private static final boolean NON_LOCKED = true;
    private static final boolean NON_PASSWORD_EXPIRED = true;
    private static final String PERSON_ID = "TEST_PERSON_ID";
    private static final String CREDENTIALS_ID = "TEST_CREDENTIALS_ID";


    @Override
    @NonNull
    public Optional<CustomUserDetails> lookupUserByUsername(@NonNull final String username) {
        return Optional.of(new CustomUserDetails(
                USERNAME,
                PASSWORD_BCRYPT_HASHED,
                NON_LOCKED,
                NON_PASSWORD_EXPIRED,
                PERSON_ID,
                CREDENTIALS_ID));
    }

    @Override
    @NonNull
    public Optional<CustomUserDetails> lookupUserByIdentityProviderMapping(@NonNull final String identityProviderId,
                                                                           @NonNull final String mappingAttributeValue) {
        return Optional.of(new CustomUserDetails(
                USERNAME,
                PASSWORD_BCRYPT_HASHED,
                NON_LOCKED,
                NON_PASSWORD_EXPIRED,
                PERSON_ID,
                CREDENTIALS_ID));
    }
}
