package eu.firmax.cms.auth.idp.openid.clientregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * {@link OidcIdentityProviderRepository} implementation which uses preconfigured OIDC identity provider settings.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Profile("test")
@Primary
public class TestOidcIdentityProviderRepository implements OidcIdentityProviderRepository {

    public static final String KEYCLOAK_OIDC_PROVIDER_ID = "KEYCLOAK_OIDC_PROVIDER_ID";
    private static final boolean USE_DISCOVERY = true;
    private static final String ISSUER_URL = "http://127.0.0.1:8080/realms/master";
    private static final String AUTHORIZATION_URL = null;
    private static final String JWKS_URL = null;
    private static final String USER_INFO_URL = null;
    private static final String TOKEN_URL = null;
    private static final String CLIENT_ID = "companyxoidc";
    private static final String CLIENT_SECRET = "RaurwG0u56rWMWV3rF9aPE19RYGyTwBB";

    @Override
    @NonNull
    public Map<String, OidcProviderSettings> loadOidcSettings(@NonNull final Set<String> identityProviderIds) {
        final List<String> scopes = List.of("openid");
        final OidcProviderSettings oidcProviderSettings = new OidcProviderSettings(
                USE_DISCOVERY, ISSUER_URL, AUTHORIZATION_URL, JWKS_URL, USER_INFO_URL, TOKEN_URL, CLIENT_ID, CLIENT_SECRET, scopes);
        return Map.of(KEYCLOAK_OIDC_PROVIDER_ID, oidcProviderSettings);
    }
}
