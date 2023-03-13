package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.jwk.JWK;
import edu.umd.cs.findbugs.annotations.NonNull;

import java.util.List;

/**
 * Base interface for classes/interfaces which implement a repository for {@link StoredJwk} information.
 */
public interface JwtKeyStoreRepository {

    /**
     * Returns a list of {@link StoredJwk}'s, which are applicable for the creation of {@link JWK}.
     *
     * @return a list of {@link StoredJwk}'s, which are applicable for the creation of {@link JWK}.
     */
    @NonNull
    List<StoredJwk> getValidJwks();

    /**
     * Saves the given {@link StoredJwk}.
     */
    void createJwk(@NonNull final StoredJwk jwks);
}
