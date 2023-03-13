package eu.firmax.cms.auth.idp.saml.relyingpartyregistration;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.IdentityProvider;
import eu.firmax.cms.auth.idp.IdentityProviderCache;
import eu.firmax.cms.auth.idp.IdentityProviderType;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.idp.saml.serviceproviderinformation.SamlCertificateCache;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKey;
import eu.firmax.cms.auth.security.FederatedIdentityConfigurer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service that handles the creation of {@link RelyingPartyRegistration}s.
 * Used to fill the {@link SamlIdentityProviderCache}.
 */
@Component
@RequiredArgsConstructor
public class RelyingPartyRegistrationService {

    @NonNull
    private final IdentityProviderCache identityProviderCache;

    @NonNull
    private final SamlCertificateCache samlCertificateCache;

    @NonNull
    private final SamlIdentityProviderRepository samlIdentityProviderRepository;

    @NonNull
    private final SamlIdentityProviderEndpointProperties samlIdentityProviderEndpointProperties;

    /**
     * Creates all {@link RelyingPartyRegistration}'s for the {@link IdentityProvider}s which the
     * resource server has configured and use the SAML standard.
     * The name of the IdentityProvider will be used as the RelyingParty registration id,
     * therefore the created map is RelyingPartyRegistration to the name of the IdentityProvider.
     * <p>
     * It will be configured that for all registrations our authentication requests will be signed,
     * independent of the concrete setting in the metadata of the identity provider.
     *
     * @return a map of created {@link RelyingPartyRegistration} to a {@link IdentityProvider#name()}, for which the
     * registrations have been created. The name of the identity provider is used as the registration id.
     */
    @NonNull
    public Map<String, RelyingPartyRegistration> createRelyingPartyRegistrations() {
        final List<IdentityProvider> identityProviders = identityProviderCache.getIdentityProviders().stream()
                .filter(identityProvider -> identityProvider.identityProviderType() == IdentityProviderType.SAML)
                .collect(Collectors.toList());
        final CertificateAndPrivateKey samlCertificateAndPrivateKey = samlCertificateCache.getSamlCertificate();

        return createRelyingPartyRegistrations(identityProviders, samlCertificateAndPrivateKey);
    }

    /**
     * Creates {@link RelyingPartyRegistration}'s for the given {@link IdentityProvider}s, by determining first which
     * of the providers use the SAML standard and collects the corresponding SAML specific settings for that provider.
     * <p>
     * Maps the created {@link RelyingPartyRegistration}'s to the {@link IdentityProvider#name()}, for which the registration
     * has been created.
     * <p>
     * The certificate and private key information is need in order to configure the to be used signing and
     * decryption credentials, which will be used to either sign our authentication requests for the identity provider
     * or decrypt received saml assertions.
     *
     * @param identityProviders            The {@link IdentityProvider}'s for which the {@link RelyingPartyRegistration} should be created.
     * @param samlCertificateAndPrivateKey the public and private key information used to sign saml auth requests and to decrypt assertions.
     * @return a map of created {@link RelyingPartyRegistration} to a {@link IdentityProvider#name()}, for which the
     * registrations have been created.
     */
    @NonNull
    private Map<String, RelyingPartyRegistration> createRelyingPartyRegistrations(@NonNull final List<IdentityProvider> identityProviders,
                                                                                  @NonNull final CertificateAndPrivateKey samlCertificateAndPrivateKey) {
        if (identityProviders.isEmpty()) {
            return Collections.emptyMap();
        }

        final Set<String> identityProviderIds = identityProviders.stream()
                .map(IdentityProvider::id)
                .collect(Collectors.toSet());

        final Map<String, SamlIdentityProviderRepository.SamlProviderSettings> identityProviderIdToSettings =
                samlIdentityProviderRepository.loadSamlSettings(identityProviderIds);

        return identityProviders.stream()
                .collect(Collectors.toUnmodifiableMap(
                        IdentityProvider::name,
                        idp -> createSamlIdentityProvider(idp, identityProviderIdToSettings.get(idp.id()), samlCertificateAndPrivateKey)));
    }

    /**
     * Creates a {@link RelyingPartyRegistration} for the given {@link IdentityProvider} with the given combination of
     * saml specific settings and saml certificate/privateKey settings.
     * <p>
     * The id of the registration is set to the name of the identity provider, in order to distinguish the different
     * registration easier.
     * <p>
     * The same certificate and private key is used for signing and encryption/decryption.
     * <p>
     * It will be configured that for all registrations our authentication requests will be signed,
     * independent of the concrete setting in the metadata of the identity provider.
     *
     * @param identityProvider             The {@link IdentityProvider} for which the {@link RelyingPartyRegistration} should be created.
     * @param samlSettings                 The settings which should be used in combination with the given {@link IdentityProvider}.
     * @param samlCertificateAndPrivateKey The certificate and private key which should be used in combination with the given {@link IdentityProvider}.
     * @return a {@link RelyingPartyRegistration} which represents the registration of this application with the given SAML based {@link IdentityProvider}.
     */
    @NonNull
    private RelyingPartyRegistration createSamlIdentityProvider(@NonNull final IdentityProvider identityProvider,
                                                                @NonNull final SamlIdentityProviderRepository.SamlProviderSettings samlSettings,
                                                                @NonNull final CertificateAndPrivateKey samlCertificateAndPrivateKey) {
        return RelyingPartyRegistrations
                .fromMetadataLocation(samlSettings.issuerUrl())
                .registrationId(identityProvider.name())
                .entityId(FederatedIdentityConfigurer.BASE_URL_VARIABLE + samlIdentityProviderEndpointProperties.getSpMetaDataEndpoint())
                .singleLogoutServiceLocation(FederatedIdentityConfigurer.BASE_URL_VARIABLE + samlIdentityProviderEndpointProperties.getLogoutRequestEndpoint())
                .assertionConsumerServiceLocation(FederatedIdentityConfigurer.BASE_URL_VARIABLE + samlIdentityProviderEndpointProperties.getLoginProcessingEndpoint())
                .assertingPartyDetails(party -> party.wantAuthnRequestsSigned(true))
                .signingX509Credentials(credentials -> credentials.add(Saml2X509Credential.signing(samlCertificateAndPrivateKey.privateKey(), samlCertificateAndPrivateKey.x509Certificate())))
                .decryptionX509Credentials(credentials -> credentials.add(Saml2X509Credential.decryption(samlCertificateAndPrivateKey.privateKey(), samlCertificateAndPrivateKey.x509Certificate())))
                .build();
    }

}
