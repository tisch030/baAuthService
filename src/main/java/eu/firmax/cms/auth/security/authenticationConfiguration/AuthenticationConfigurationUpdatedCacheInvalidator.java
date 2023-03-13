package eu.firmax.cms.auth.security.authenticationConfiguration;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.context.event.EventListener;

/**
 * Basic interface for implementations/interfaces that provide a caching mechanism depending on identity
 * provider information.
 * It must be implemented by classes/interfaces that implement a cache that should be invalidated and
 * rebuild as soon as identity providers configurations got changed.
 */
public interface AuthenticationConfigurationUpdatedCacheInvalidator {

    /**
     * Handles the {@link AuthenticationConfigurationUpdatedEvent} which indicates that the identity provider
     * configurations got updated and the caches should get rebuild.
     *
     * @param event the event indicating that the identity provider configurations got updated.
     */
    @EventListener
    void authenticationConfigurationUpdatedEventListener(@NonNull final AuthenticationConfigurationUpdatedEvent event);
}
