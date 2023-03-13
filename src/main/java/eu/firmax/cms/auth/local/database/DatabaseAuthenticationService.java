package eu.firmax.cms.auth.local.database;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettings;
import eu.firmax.cms.auth.local.settings.LocalAuthenticationSettingsCache;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service that handles the creation of a {@link AuthenticationProvider} which should be used for local
 * authentication (i.e. username/password).
 * <p>
 * Creates a {@link DaoAuthenticationProvider} with the global {@link PasswordEncoder} and {@link DatabaseUserDetailsService} set,
 * only if the local authentication is enabled.
 * The information about the status of local authentication is stored in the {@link LocalAuthenticationSettingsCache}.
 */
@Service
@RequiredArgsConstructor
public class DatabaseAuthenticationService {

    @NonNull
    private final DatabaseUserDetailsService userDetailsService;

    @NonNull
    private final LocalAuthenticationSettingsCache localAuthenticationSettingsCache;

    @NonNull
    private final PasswordEncoder passwordEncoder;

    @Nullable
    public AuthenticationProvider createDatabaseAuthenticationProvider() {
        final LocalAuthenticationSettings localAuthenticationSettings = localAuthenticationSettingsCache.getLocalAuthenticationSettings();
        if (localAuthenticationSettings == null) {
            return null;
        }

        final DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
