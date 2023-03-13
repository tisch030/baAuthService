package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Service which handles the loading of {@link IdentityProvider} information.
 * Is seperated from the {@link IdentityProviderService}, because otherwise a dependency cycle
 * between the {@link CaffeineIdentityProviderCache} and {@link IdentityProviderService} will be formed.
 */
@Component
@RequiredArgsConstructor
public class IdentityProviderLoadService {

    @NonNull
    private final IdentityProviderRepository identityProviderRepository;

    /**
     * Returns a list of all enabled {@link IdentityProvider}'s, ordered ascending
     * by the priority of the identity provider.
     *
     * @return a list of enabled {@link IdentityProvider}'s, ordered ascending
     * by the priority of the identity provider.
     */
    @NonNull
    public List<IdentityProvider> loadIdentityProviders() {
        return identityProviderRepository.loadEnabledIdentityProvidersOrderedByPriority();

    }

    /**
     * Returns the id of the given identity providers name.
     *
     * @return the id of the given identity providers name.
     */
    @NonNull
    public String loadIdentityProviderId(@NonNull final String identityProviderName) {
        return identityProviderRepository.loadIdentityProviderId(identityProviderName);
    }
}
