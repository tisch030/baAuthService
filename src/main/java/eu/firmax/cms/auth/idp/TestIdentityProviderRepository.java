package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.openid.clientregistration.TestOidcIdentityProviderRepository;
import eu.firmax.cms.auth.idp.saml.relyingpartyregistration.TestSamlIdentityProviderRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link IdentityProviderRepository} implementation which uses preconfigured identity provider information.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Profile("test")
@Primary
public class TestIdentityProviderRepository implements IdentityProviderRepository {

    private static final String KEYCLOAK_SAML_PROVIDER_ID = TestSamlIdentityProviderRepository.KEYCLOAK_SAML_PROVIDER_ID;
    public static final String KEYCLOAK_SAML_PROVIDER_NAME = "companyxsaml";
    private static final boolean KEYCLOAK_SAML_PROVIDER_ENABLED = true;
    private static final int KEYCLOAK_SAML_PROVIDER_POSITION = 998;
    private static final String KEYCLOAK_SAML_PROVIDER_BUTTON_LABEL = "KeyCloak CompanyX SAML";
    private static final IdentityProviderType KEYCLOAK_SAML_PROVIDER_TYPE = IdentityProviderType.SAML;

    private static final String KEYCLOAK_OIDC_PROVIDER_ID = TestOidcIdentityProviderRepository.KEYCLOAK_OIDC_PROVIDER_ID;
    private static final String KEYCLOAK_OIDC_PROVIDER_NAME = "companyxoidc";
    private static final boolean KEYCLOAK_OIDC_PROVIDER_ENABLED = true;
    private static final int KEYCLOAK_OIDC_PROVIDER_POSITION = 999;
    private static final String KEYCLOAK_OIDC_PROVIDER_BUTTON_LABEL = "KeyCloak CompanyX OIDC";
    private static final IdentityProviderType KEYCLOAK_OIDC_PROVIDER_TYPE = IdentityProviderType.OPENID_CONNECT;

    private static final String ATTRIBUTE_MAPPING_IDP_ATTRIBUTE = "bPK2";

    @Override
    @NonNull
    public List<IdentityProvider> loadEnabledIdentityProvidersOrderedByPriority() {

        final IdentityProvider keycloakSamlIdentityProvider = new IdentityProvider(
                KEYCLOAK_SAML_PROVIDER_ID,
                KEYCLOAK_SAML_PROVIDER_NAME,
                KEYCLOAK_SAML_PROVIDER_ENABLED,
                KEYCLOAK_SAML_PROVIDER_POSITION,
                KEYCLOAK_SAML_PROVIDER_BUTTON_LABEL,
                KEYCLOAK_SAML_PROVIDER_TYPE,
                ATTRIBUTE_MAPPING_IDP_ATTRIBUTE
        );

        final IdentityProvider keycloakOidcIdentityProvider = new IdentityProvider(
                KEYCLOAK_OIDC_PROVIDER_ID,
                KEYCLOAK_OIDC_PROVIDER_NAME,
                KEYCLOAK_OIDC_PROVIDER_ENABLED,
                KEYCLOAK_OIDC_PROVIDER_POSITION,
                KEYCLOAK_OIDC_PROVIDER_BUTTON_LABEL,
                KEYCLOAK_OIDC_PROVIDER_TYPE,
                ATTRIBUTE_MAPPING_IDP_ATTRIBUTE
        );

        return Stream.of(keycloakOidcIdentityProvider, keycloakSamlIdentityProvider)
                .sorted(Comparator.comparing(IdentityProvider::position)).collect(Collectors.toList());
    }

    @Override
    @NonNull
    public String loadIdentityProviderId(@NonNull String identityProviderName) {
        if (identityProviderName.equals(KEYCLOAK_SAML_PROVIDER_NAME)) {
            return KEYCLOAK_SAML_PROVIDER_ID;
        } else {
            return KEYCLOAK_OIDC_PROVIDER_ID;
        }
    }
}
