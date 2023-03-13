package eu.firmax.cms.auth.security.authenticationConfiguration;

/**
 * Used as an indicator event whenever the identity provider configurations changed.
 * All services using information from a identity provider should refresh their information upon receiving this event.
 */
public class AuthenticationConfigurationUpdatedEvent {
}
