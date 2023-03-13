package eu.firmax.cms.auth.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

/**
 * Glue code to forward any spring request for {@link RegisteredClient}s to the {@link RegisteredClientCache}.
 * Doesn't implement dynamic client registration, since we don't want to allow the dynamic registration.
 */
@Component
@RequiredArgsConstructor
public class DynamicRegisteredClientRepository implements RegisteredClientRepository {

    @NonNull
    private final RegisteredClientCache registeredClientCache;

    @Override
    public void save(@NonNull final RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Dynamic client registration is not supported!");
    }

    @Override
    @Nullable
    public RegisteredClient findById(@NonNull final String id) {
        return registeredClientCache.getRegisteredClientById(id);
    }

    @Override
    @Nullable
    public RegisteredClient findByClientId(@NonNull final String clientId) {
        // The clients that are build have id == clientId.
        return registeredClientCache.getRegisteredClientById(clientId);
    }
}
