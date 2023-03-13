package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Base interface for classes/interfaces which implement a repository for {@link SamlServiceProviderMetadata}.
 */
public interface SamlServiceProviderMetadataRepository {

    /**
     * Returns the SAML metadata.
     *
     * @return the SAML metadata.
     */
    @NonNull
    SamlServiceProviderMetadata getSamlServiceProviderMetaData();
}
