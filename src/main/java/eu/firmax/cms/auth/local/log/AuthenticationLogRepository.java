package eu.firmax.cms.auth.local.log;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Base interface for classes/interfaces which implement a repository for persisting authentication log information.
 */
public interface AuthenticationLogRepository {

    /**
     * Saves a log entry.
     *
     * @param authenticationOperation The operation which should be logged.
     * @param personId                The id of a person which has been used for the operation.
     * @param username                The username which has been used for the operation.
     * @param ipAddress               The ip address which has been used for the operation.
     */
    void writeLogEntry(@NonNull final AuthenticationOperation authenticationOperation,
                       @Nullable final String personId,
                       @Nullable final String username,
                       @Nullable final String ipAddress);
}
