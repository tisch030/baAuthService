package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;


import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.bundid.StorkQaaLevel;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Set;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.IdentityProvider.IDENTITY_PROVIDER;
import static eu.companyx.cms.auth.dto.companyx_backend.tables.SamlSettings.SAML_SETTINGS;

/**
 * {@link SamlIdentityProviderRepository} implementation which uses JOOQ to access the SAML settings in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqSamlIdentityProviderRepository implements SamlIdentityProviderRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @NonNull
    public Map<String, SamlProviderSettings> loadSamlSettings(@NonNull final Set<String> identityProviderIds) {

        return dsl.select(
                        SAML_SETTINGS.IDENTITY_PROVIDER_ID,
                        SAML_SETTINGS.ISSUER_URL,
                        SAML_SETTINGS.STORK_QAA_LEVEL)
                .from(SAML_SETTINGS)
                .where(SAML_SETTINGS.IDENTITY_PROVIDER_ID.in(identityProviderIds))
                .fetchMap(
                        row -> row.get(SAML_SETTINGS.IDENTITY_PROVIDER_ID),
                        row -> new SamlProviderSettings(
                                row.get(SAML_SETTINGS.ISSUER_URL),
                                row.get(SAML_SETTINGS.STORK_QAA_LEVEL) == null ?
                                        null :
                                        StorkQaaLevel.valueOf(row.get(SAML_SETTINGS.STORK_QAA_LEVEL))
                        ));
    }

    @Override
    @NonNull
    public Map<String, SamlProviderSettings> loadAllSamlSettingsMappedByIdentityProviderName() {
        return dsl.select(
                        IDENTITY_PROVIDER.NAME,
                        SAML_SETTINGS.ISSUER_URL,
                        SAML_SETTINGS.STORK_QAA_LEVEL)
                .from(SAML_SETTINGS)
                .leftJoin(IDENTITY_PROVIDER).on(IDENTITY_PROVIDER.ID.eq(SAML_SETTINGS.IDENTITY_PROVIDER_ID))
                .fetchMap(
                        row -> row.get(IDENTITY_PROVIDER.NAME),
                        row -> new SamlProviderSettings(
                                row.get(SAML_SETTINGS.ISSUER_URL),
                                row.get(SAML_SETTINGS.STORK_QAA_LEVEL) == null ?
                                        null :
                                        StorkQaaLevel.valueOf(row.get(SAML_SETTINGS.STORK_QAA_LEVEL))
                        ));
    }
}
