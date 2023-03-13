package eu.firmax.cms.auth.local.database;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.user.CustomUserDetails;

import java.util.Optional;

/**
 * Base interface for classes/interfaces which implement a repository for {@link CustomUserDetails}.
 */
public interface UserDetailsRepository {

    /**
     * Returns the {@link CustomUserDetails} of a user based on the username or an empty {@link Optional}
     * if no user with the given username could be found.
     * Depending on the actual implementation, the lookup by username can be either case-sensitive or not,
     * which would lead to a different username inside {@link CustomUserDetails} than the given username.
     *
     * @param username The username identifying the user whose data should be retrieved.
     * @return the {@link CustomUserDetails} of a user based on the username or an empty {@link Optional}
     * if no user with the given username could be found.
     */
    @NonNull
    Optional<CustomUserDetails> lookupUserByUsername(@NonNull final String username);

    /**
     * Returns the {@link CustomUserDetails} of a user by matching the given mapping attribute value to the
     * mapping attribute value stored for the given identity provider.
     * Returns an empty {@link Optional} if no user with the given mapping attribute value could be found.
     *
     * @param identityProviderId    The identity provider which provides the mapping value in order to determine
     *                              the user.
     * @param mappingAttributeValue The value by which the user should be identified by.
     * @return the {@link CustomUserDetails} of a user by matching the given mapping attribute value to the
     * mapping attribute value stored for the given identity provider.
     * Returns an empty {@link Optional} if no user with the given mapping attribute value could be found.
     */
    @NonNull
    Optional<CustomUserDetails> lookupUserByIdentityProviderMapping(@NonNull final String identityProviderId,
                                                                    @NonNull final String mappingAttributeValue);
}
