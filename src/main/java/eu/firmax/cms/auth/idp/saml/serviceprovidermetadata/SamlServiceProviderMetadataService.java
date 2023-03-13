package eu.firmax.cms.auth.idp.saml.serviceprovidermetadata;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderEndpointProperties;
import eu.firmax.cms.auth.idp.saml.SamlIdentityProviderProperties;
import eu.firmax.cms.auth.idp.saml.serviceproviderinformation.SamlCertificateCache;
import lombok.RequiredArgsConstructor;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.GivenName;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.ContactPersonBuilder;
import org.opensaml.saml.saml2.metadata.impl.EmailAddressBuilder;
import org.opensaml.saml.saml2.metadata.impl.GivenNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationDisplayNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationURLBuilder;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service that handles the creation of the SAML metadata.
 * The metadata is published as a file to download via an endpoint from the authorization server
 * and are made public to the SAML identity providers.
 */
@Service
@RequiredArgsConstructor
public class SamlServiceProviderMetadataService {

    @NonNull
    private final SamlCertificateCache samlCertificateCache;

    @NonNull
    private final SamlServiceProviderMetadataRepository samlServiceProviderMetadataRepository;

    @NonNull
    private final SamlIdentityProviderEndpointProperties samlIdentityProviderEndpointProperties;

    @NonNull
    private final SamlIdentityProviderProperties samlIdentityProviderProperties;


    /**
     * Returns the {@link SamlServiceProviderMetadata}.
     *
     * @return the {@link SamlServiceProviderMetadata}.
     */
    @NonNull
    public SamlServiceProviderMetadata loadSamlServiceProviderMetadata() {
        return samlServiceProviderMetadataRepository.getSamlServiceProviderMetaData();
    }

    /**
     * Creates a {@link Saml2MetadataFilter} which handles requests to get the SAML metadata.
     * The returned data must be made public to the identity provider, so they know how to communicate with us.
     * <p>
     * The metadata provided by the {@link OpenSamlMetadataResolver} contains the information which have been
     * extracted from the {@link RelyingPartyRegistration}.
     * <p>
     * We customize that metadata by including the following additional information (needed especially for BundId):
     * <ul>
     *     <li>Organization: OrganizationName, OrganizationDisplayName and OrganizationUrl</li>
     *     <li>ContactPerson (Technical and Supportive): Name and Mail</li>
     *     <li>Metadata valid timespan: Information inside the Metadata are valid until the expiration date of the
     *     corresponding used certificate</li>
     *     <li>Explicit stating that we sign our requests and want also in return signed responses</li>
     * </ul>
     *
     * @param relyingPartyRegistrationResolver used by the {@link Saml2MetadataFilter} to determine the {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration} for the request.
     * @param samlServiceProviderMetadataCache cache that contains the SAML metadata which we want to add.
     * @return a {@link Saml2MetadataFilter} which handles requests to get the SAML metadata.
     */
    @NonNull
    public Saml2MetadataFilter createRelyingPartyMetaDataEndpointFilter(@NonNull final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                                                        @NonNull final SamlServiceProviderMetadataCache samlServiceProviderMetadataCache) {

        // Add custom metadata xml attributes like organization and contact person to SP metadata.
        final OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
        openSamlMetadataResolver.setEntityDescriptorCustomizer(entityDescriptorParameters ->
                customizeSamlMetadataResponse(samlServiceProviderMetadataCache, entityDescriptorParameters));

        // Create metadata endpoint filter and customize request matcher.
        final Saml2MetadataFilter relyingPartyMetaDataEndpointFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, openSamlMetadataResolver);
        relyingPartyMetaDataEndpointFilter.setRequestMatcher(new AntPathRequestMatcher(samlIdentityProviderEndpointProperties.getSpMetaDataEndpoint(), "GET"));

        return relyingPartyMetaDataEndpointFilter;
    }

    private void customizeSamlMetadataResponse(@NonNull final SamlServiceProviderMetadataCache samlServiceProviderMetadataCache,
                                               @NonNull final OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {

        final EntityDescriptor entityDescriptor = entityDescriptorParameters.getEntityDescriptor();
        final SamlServiceProviderMetadata metadata = samlServiceProviderMetadataCache.getMetadata();

        final Organization organization = generateOrganization(metadata);
        final List<ContactPerson> contactPersons = generateContactPerson(metadata);
        entityDescriptor.setOrganization(organization);
        entityDescriptor.getContactPersons().addAll(contactPersons);
        entityDescriptor.setValidUntil(samlCertificateCache.getSamlCertificate().x509Certificate().getNotAfter().toInstant());

        final SPSSODescriptor spssoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        spssoDescriptor.setWantAssertionsSigned(true);
        spssoDescriptor.setAuthnRequestsSigned(true);
    }

    /**
     * Creates a {@link Organization} xml-attribute for the use inside a SAML metadata file.
     * If no display name is specified for the organization, the name of the organization is used as a fallback.
     *
     * @param samlServiceProviderMetadata {@link SamlServiceProviderMetadata} which contains the information about an organization.
     * @return a {@link Organization} xml-attribute for the use inside a SAML metadata file.
     */
    @NonNull
    private Organization generateOrganization(@NonNull final SamlServiceProviderMetadata samlServiceProviderMetadata) {

        final OrganizationBuilder organizationBuilder = new OrganizationBuilder();
        final Organization organization = organizationBuilder.buildObject();
        organization.getOrganizationNames().add(createOrganizationName(samlServiceProviderMetadata));
        organization.getDisplayNames().add(createOrganizationDisplayName(samlServiceProviderMetadata));
        organization.getURLs().add(createOrganizationURL(samlServiceProviderMetadata));

        return organization;
    }

    @NonNull
    private OrganizationName createOrganizationName(@NonNull final SamlServiceProviderMetadata samlServiceProviderMetadata) {

        final OrganizationNameBuilder organizationNameBuilder = new OrganizationNameBuilder();
        final OrganizationName organizationName = organizationNameBuilder.buildObject();
        organizationName.setXMLLang("en");
        organizationName.setValue(samlServiceProviderMetadata.organizationName());
        return organizationName;
    }

    @NonNull
    private OrganizationDisplayName createOrganizationDisplayName(@NonNull final SamlServiceProviderMetadata samlServiceProviderMetadata) {

        final String organizationDisplayNameValue = samlServiceProviderMetadata.organizationDisplayName() != null ?
                samlServiceProviderMetadata.organizationDisplayName() :
                samlServiceProviderMetadata.organizationName();

        final OrganizationDisplayNameBuilder displayNameBuilder = new OrganizationDisplayNameBuilder();
        final OrganizationDisplayName organizationDisplayName = displayNameBuilder.buildObject();
        organizationDisplayName.setXMLLang("en");
        organizationDisplayName.setValue(organizationDisplayNameValue);
        return organizationDisplayName;
    }

    @NonNull
    private OrganizationURL createOrganizationURL(@NonNull final SamlServiceProviderMetadata samlServiceProviderMetadata) {

        final OrganizationURLBuilder organizationURLBuilder = new OrganizationURLBuilder();
        final OrganizationURL organizationURL = organizationURLBuilder.buildObject();
        organizationURL.setXMLLang("en");
        organizationURL.setURI(samlServiceProviderMetadata.organizationUrl());
        return organizationURL;
    }

    /**
     * Creates a list of {@link ContactPerson} xml-attributes for the use inside a SAML metadata file.
     * Contains the technical contact person from the properties and the support contact person as
     * configured in the resource server.
     *
     * @param samlServiceProviderMetadata {@link SamlServiceProviderMetadata} which contains the information about the contact persons.
     * @return a list of {@link ContactPerson} xml-attributes for the use inside a SAML metadata file.
     */
    @NonNull
    private List<ContactPerson> generateContactPerson(@NonNull final SamlServiceProviderMetadata samlServiceProviderMetadata) {

        final ContactPerson technicalContactPerson = createContactPerson(
                samlIdentityProviderProperties.getSpMetadataTechnicalContactPersonName(),
                samlIdentityProviderProperties.getSpMetadataTechnicalContactPersonMail(),
                ContactPersonTypeEnumeration.TECHNICAL);

        final ContactPerson supportContactPerson = createContactPerson(
                samlServiceProviderMetadata.supportContactPersonName(),
                samlServiceProviderMetadata.supportContactPersonMail(),
                ContactPersonTypeEnumeration.SUPPORT);

        final List<ContactPerson> contactPersons = new ArrayList<>(2);
        contactPersons.add(technicalContactPerson);
        contactPersons.add(supportContactPerson);
        return contactPersons;
    }

    @NonNull
    private ContactPerson createContactPerson(@NonNull final String personName,
                                              @NonNull final String personEmail,
                                              @NonNull final ContactPersonTypeEnumeration contactType) {

        final GivenName supportPersonName = new GivenNameBuilder().buildObject();
        supportPersonName.setValue(personName);

        final EmailAddress supportPersonMail = new EmailAddressBuilder().buildObject();
        supportPersonMail.setURI(personEmail);

        final ContactPerson supportContactPerson = new ContactPersonBuilder().buildObject();
        supportContactPerson.setType(contactType);
        supportContactPerson.setGivenName(supportPersonName);
        supportContactPerson.getEmailAddresses().add(supportPersonMail);
        return supportContactPerson;
    }
}
