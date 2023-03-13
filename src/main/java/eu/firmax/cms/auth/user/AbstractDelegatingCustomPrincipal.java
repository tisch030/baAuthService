package eu.firmax.cms.auth.user;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * A principal which delegates all method calls to another principal wrapped inside this one.
 */
@RequiredArgsConstructor
public abstract class AbstractDelegatingCustomPrincipal implements CustomPrincipal {

    @NonNull
    private final CustomPrincipal principal;

    @Nullable
    @Override
    public String getCredentialId() {
        return this.principal.getCredentialId();
    }

    @Nullable
    @Override
    public String getPersonId() {
        return this.principal.getPersonId();
    }

    @Nullable
    @Override
    public String getUsername() {
        return this.principal.getUsername();
    }

    @Nullable
    public CustomPrincipal getPrincipal() {
        return this.principal;
    }

    @Override
    @NonNull
    public String toString() {
        return getClass().getName() + "[principal=" + principal + "]";
    }
}
