package eu.firmax.cms.auth.idp.saml.samlsettings;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.relyingpartyregistration.SamlIdentityProviderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Used to fill the {@link SamlSettingsCache}.
 */
@Component
@RequiredArgsConstructor
public class SamlSettingsLoadService {

    @NonNull
    private final SamlIdentityProviderRepository samlIdentityProviderRepository;

    /**
     * Returns a map from identity provider name to their SAML specific settings.
     *
     * @return a map from identity provider name to their SAML specific settings.
     */
    @NonNull
    public Map<String, SamlIdentityProviderRepository.SamlProviderSettings> loadSamlSettings() {
        return samlIdentityProviderRepository.loadAllSamlSettingsMappedByIdentityProviderName();

    }
}
