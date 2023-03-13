package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

/**
 * {@link SamlServiceProviderMetadataRepository} implementation which uses preconfigured SAML metadata.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Primary
@Profile("test")
public class TestSamlServiceProviderMetadata implements SamlServiceProviderMetadataRepository {

    private static final String UNIVERSITY_NAME = "TEST_UNI";
    private static final String UNIVERSITY_DISPLAY_NAME = "TEST_UNI_DISPLAY";
    private static final String UNIVERSITY_URL = "TEST_UNI_URL";
    private static final String CONTACT_PERSON_NAME = "TEST_UNI_CONTACT_NAME";
    private static final String CONTACT_PERSON_MAIL = "TEST_UNI_CONTACT_MAIL";

    @Override
    @NonNull
    public SamlServiceProviderMetadata getSamlServiceProviderMetaData() {
        return new SamlServiceProviderMetadata(UNIVERSITY_NAME, UNIVERSITY_DISPLAY_NAME,
                UNIVERSITY_URL, CONTACT_PERSON_NAME, CONTACT_PERSON_MAIL);
    }
}
