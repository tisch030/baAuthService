package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.TemplateSettings.TEMPLATE_SETTINGS;

/**
 * {@link SamlServiceProviderMetadataRepository} implementation which uses JOOQ to access the SAML metadata in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqSamlServiceProviderMetadata implements SamlServiceProviderMetadataRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @NonNull
    public SamlServiceProviderMetadata getSamlServiceProviderMetaData() {
        return dsl.select(
                        TEMPLATE_SETTINGS.UNIVERSITY_NAME,
                        TEMPLATE_SETTINGS.UNIVERSITY_DISPLAY_NAME,
                        TEMPLATE_SETTINGS.UNIVERSITY_URL,
                        TEMPLATE_SETTINGS.CONTACT_PERSON_NAME,
                        TEMPLATE_SETTINGS.CONTACT_PERSON_MAIL)
                .from(TEMPLATE_SETTINGS)
                .fetchOptionalInto(SamlServiceProviderMetadata.class)
                .orElseThrow(() -> new UnsupportedOperationException("SAML metadata could not be loaded from database."));
    }
}
