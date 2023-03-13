package eu.firmax.cms.auth.idp.correlation;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.companyx.cms.auth.dto.companyx_backend.tables.CredentialIdentityProviderCorrelation;

/**
 * Base interface for classes/interfaces which implement a repository for the {@link CredentialIdentityProviderCorrelation} table,
 * that saves the correlation between the provided authentication information from an identity provider to a pair of
 * local credentials of a user.
 */
public interface CorrelationRepository {


    /**
     * Saves the given correlation values.
     * We need to store the identity provider because the correlation value could be, for example,
     * a username that is not necessarily unique across multiple providers
     * and thus can be exploited for identity theft if we map them wrong.
     *
     * @param correlationValue   the value with which a user can be uniquely identified at an identity provider.
     * @param credentialsId      the id of a users' credential to be associated with the correlation value.
     * @param identityProviderId the id of the identity provider who provided the correlation value.
     */
    void saveCorrelation(@NonNull final String correlationValue,
                         @NonNull final String credentialsId,
                         @NonNull final String identityProviderId);
}
