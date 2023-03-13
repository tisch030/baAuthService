package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;


import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.TestIdentityProviderRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Set;

/**
 * {@link SamlIdentityProviderRepository} implementation which uses preconfigured SAML identity provider settings.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Primary
@Profile("test")
public class TestSamlIdentityProviderRepository implements SamlIdentityProviderRepository {

    public static final String KEYCLOAK_SAML_PROVIDER_ID = "KEYCLOAK_SAML_PROVIDER_ID";
    private static final String KEYCLOAK_SAML_PROVIDER_ISSUER_URL = "http://127.0.0.1:8080/realms/master/protocol/saml/descriptor";

    @Override
    @NonNull
    public Map<String, SamlProviderSettings> loadSamlSettings(@NonNull final Set<String> identityProviderIds) {
        final SamlProviderSettings keyCloakSamlProviderSettings = new SamlProviderSettings(KEYCLOAK_SAML_PROVIDER_ISSUER_URL, null);
        return Map.of(KEYCLOAK_SAML_PROVIDER_ID, keyCloakSamlProviderSettings);
    }

    @Override
    @NonNull
    public Map<String, SamlProviderSettings> loadAllSamlSettingsMappedByIdentityProviderName() {
        final SamlProviderSettings keyCloakSamlProviderSettings = new SamlProviderSettings(KEYCLOAK_SAML_PROVIDER_ISSUER_URL, null);
        return Map.of(TestIdentityProviderRepository.KEYCLOAK_SAML_PROVIDER_NAME, keyCloakSamlProviderSettings);
    }
}
