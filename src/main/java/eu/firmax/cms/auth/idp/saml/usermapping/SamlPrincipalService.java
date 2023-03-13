package eu.firmax.cms.auth.idp.saml.usermapping;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.idp.IdentityProviderService;
import eu.firmax.cms.auth.idp.openid.usermapping.OidcPrincipalService;
import eu.firmax.cms.auth.local.database.UserDetailsRepository;
import eu.firmax.cms.auth.user.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles the conversion of SAML responses to {@link Saml2Authentication}s.
 * The implementation of this class is based upon the method
 * {@link OpenSaml4AuthenticationProvider#createDefaultResponseAuthenticationConverter} and therefore includes
 * some duplicated code of the same class, because it is not publicly available.
 * <p>
 * Does serve the same purpose as the {@link OidcPrincipalService}.
 * We want to load the user details, if we received the saml response from a user which has previously visited
 * our application and has a user profile.
 * Instead of searching for the mapping attribute in the claims, we use the saml assertion attributes and determine
 * if the attributes contain the configured unique identifier attribute.
 * If that is the case, we do a look-up in our database to determine the user profile.
 * If no user profile for the determined correlation value could be found, we create a empty user details object,
 * indicating a new user.
 */
@Component
@RequiredArgsConstructor
public class SamlPrincipalService implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> {

    @NonNull
    private final UserDetailsRepository userDetailsRepository;

    @NonNull
    private final IdentityProviderService identityProviderService;

    @Override
    @NonNull
    public Saml2Authentication convert(@NonNull final OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        final String identityProviderName = responseToken.getToken().getRelyingPartyRegistration().getRegistrationId();
        final CustomSamlPrincipal principal = retrieveUserDetails(identityProviderName, responseToken.getResponse().getAssertions());
        return new Saml2Authentication(principal, responseToken.getToken().getSaml2Response(), null);
    }

    @NonNull
    private CustomSamlPrincipal retrieveUserDetails(@NonNull final String identityProviderName,
                                                    @Nullable final List<Assertion> assertions) {

        if (assertions == null || assertions.isEmpty()) {
            throw new AuthenticationServiceException("SAML response tokens without any assertions received");
        }

        final Assertion assertion = assertions.get(0);

        final String subject = assertion.getSubject().getNameID().getValue();
        if (subject == null) {
            throw new AuthenticationServiceException("SAML response tokens without subject received");
        }

        final Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
        final List<String> sessionIndexes = getSessionIndexes(assertion);

        final CustomUserDetails userDetails = retrieveUserDetails(identityProviderName, subject, attributes);

        return new CustomSamlPrincipal(userDetails, subject, attributes, identityProviderName, sessionIndexes);
    }

    @NonNull
    private CustomUserDetails retrieveUserDetails(@NonNull final String identityProviderName,
                                                  @NonNull final String subject,
                                                  @NonNull final Map<String, List<Object>> attributes) {

        final IdentityProviderService.IdentityProviderAndUniqueIdentifierMappingAttribute mapping =
                identityProviderService.getIdentityProviderUniqueIdentifierMappingAttribute(identityProviderName)
                        .orElseThrow(() -> new AuthenticationServiceException("Unknown identity provider " + identityProviderName));

        final Object mappingValue;
        if (mapping.mappingAttribute() == null) {
            mappingValue = subject;
        } else {
            final List<Object> mappingValues = attributes.get(mapping.mappingAttribute());
            if (mappingValues == null || mappingValues.size() != 1) {
                throw new AuthenticationServiceException("The mapping attribute is not part of or doesn't have a single value in the SAML assertions in the response");
            }
            mappingValue = mappingValues.iterator().next();
            if (mappingValue == null) {
                throw new AuthenticationServiceException("The mapping attribute is not part of or doesn't have a single value in the SAML assertions in the response");
            }
        }

        return userDetailsRepository.lookupUserByIdentityProviderMapping(mapping.identityProviderId(), mappingValue.toString())
                .orElse(new CustomUserDetails(
                        null,
                        null,
                        false,
                        false,
                        null,
                        null
                ));
    }

    /*
    ===================================================================================================================
    The code below is based upon the same code from the OpenSaml4AuthenticationProvider.
    No formatting and code style changes were made.
    ===================================================================================================================
     */

    private static Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
        Map<String, List<Object>> attributeMap = new LinkedHashMap<>();
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                List<Object> attributeValues = new ArrayList<>();
                for (XMLObject xmlObject : attribute.getAttributeValues()) {
                    Object attributeValue = getXmlObjectValue(xmlObject);
                    if (attributeValue != null) {
                        attributeValues.add(attributeValue);
                    }
                }
                attributeMap.put(attribute.getName(), attributeValues);
            }
        }
        return attributeMap;
    }

    private static List<String> getSessionIndexes(Assertion assertion) {
        List<String> sessionIndexes = new ArrayList<>();
        for (AuthnStatement statement : assertion.getAuthnStatements()) {
            sessionIndexes.add(statement.getSessionIndex());
        }
        return sessionIndexes;
    }

    private static Object getXmlObjectValue(XMLObject xmlObject) {
        if (xmlObject instanceof XSAny) {
            return ((XSAny) xmlObject).getTextContent();
        } else if (xmlObject instanceof XSString) {
            return ((XSString) xmlObject).getValue();
        } else if (xmlObject instanceof XSInteger) {
            return ((XSInteger) xmlObject).getValue();
        } else if (xmlObject instanceof XSURI) {
            return ((XSURI) xmlObject).getURI();
        } else if (xmlObject instanceof XSBoolean) {
            XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
            return xsBooleanValue != null ? xsBooleanValue.getValue() : null;
        } else {
            return xmlObject instanceof XSDateTime ? ((XSDateTime) xmlObject).getValue() : xmlObject;
        }
    }
}
