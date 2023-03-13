package eu.firmax.cms.auth.idp;

import edu.umd.cs.findbugs.annotations.NonNull;

public record IdentityProvider(@NonNull String id,
                               @NonNull String name,
                               boolean enabled,
                               @NonNull Integer position,
                               @NonNull String buttonLabel,
                               @NonNull IdentityProviderType identityProviderType,
                               @NonNull String uniqueIdentifierAttribute) {
}
