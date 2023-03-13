package eu.firmax.cms.auth.local.settings;

/**
 * Container for information regarding the local authentication (e.g username/password) against a
 * database.
 *
 * @param localAuthenticationEnabled                   States if the local authentication is enabled or not.
 * @param maxFailedAttemptsPerUsernameAndIpInOneMinute How many login attempts are allowed within a timespan of one minute.
 */
public record LocalAuthenticationSettings(boolean localAuthenticationEnabled,
                                          int maxFailedAttemptsPerUsernameAndIpInOneMinute
) {
}
