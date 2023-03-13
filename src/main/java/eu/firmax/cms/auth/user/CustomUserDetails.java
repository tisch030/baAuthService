package eu.firmax.cms.auth.user;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Implementation of the Spring {@link UserDetails} which is extended by the {@link CustomPrincipal} interface.
 */
@Getter
@Setter
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails, CustomPrincipal {

    @Nullable
    private final String username;

    @Nullable
    private final String password;

    private final boolean accountNonLocked;

    private final boolean credentialsNonExpired;

    @Nullable
    private final String personId;

    @Nullable
    private final String credentialId;


    @Override
    @NonNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptySet();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    @NonNull
    public String toString() {
        return getClass().getName() + "[username=" + username +
                ", password=" + (password == null ? "" : password) +
                ", accountNonLocked=" + accountNonLocked +
                ", credentialsNonExpired=" + credentialsNonExpired +
                ", credentialId=" + credentialId +
                ", personId=" + personId + "]";
    }
}
