package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;


/**
 * Container for the additional metadata information which will be published to be used by SAML identity providers.
 */
public record SamlServiceProviderMetadata(@NonNull String organizationName,
                                          @Nullable String organizationDisplayName,
                                          @NonNull String organizationUrl,
                                          @NonNull String supportContactPersonName,
                                          @NonNull String supportContactPersonMail) {
}
