package eu.firmax.cms.auth.local.settings;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Service that handles the loading of {@link LocalAuthenticationSettings}.
 * Used to fill the {@link LocalAuthenticationSettingsCache}.
 */
@Service
@RequiredArgsConstructor
public class LocalAuthenticationSettingsService {

    @NonNull
    private final LocalAuthenticationSettingsRepository localAuthenticationSettingsRepository;

    /**
     * Returns {@link LocalAuthenticationSettingsRepository.LocalAuthenticationBaseSettings}. Null if no settings have been found.
     *
     * @return {@link LocalAuthenticationSettingsRepository.LocalAuthenticationBaseSettings}. Null if no settings have been found.
     */
    @Nullable
    public LocalAuthenticationSettings loadLocalAuthenticationSettings() {
        final LocalAuthenticationSettingsRepository.LocalAuthenticationBaseSettings settings = localAuthenticationSettingsRepository.loadSettings();
        if (settings == null) {
            return null;
        }

        return new LocalAuthenticationSettings(
                settings.enabled(),
                settings.maxFailedAttemptsPerUsernameAndIpInOneMinute()
        );
    }
}
