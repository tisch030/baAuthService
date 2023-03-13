package eu.firmax.cms.auth.idp.saml.bundid;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;

import java.util.List;

/**
 * Used to manipulate SAML requests and responses for stuff necessary to support the BundId authentication provider.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class BundIdHelper {

    // Not used anywhere, but could be useful as a template for future use cases, where the creation of a custom extension is needed.
    /*
    private static final String EXTENSION_NAMESPACE = "https://www.akdb.de/request/2018/09";
    private static final String EXTENSION_NAMESPACE_PREFIX = "akdb";

     * Returns the "extensions" element for an AuthnRequest for BundID which enables the ePK2 attribute in the answer.
     *
     * @return the "extensions" element for an AuthnRequest for BundID which enables the ePK2 attribute in the answer.



    @NonNull
    public static Extensions createExtensions() {
        // Build extension element which contains BundID specific authentication request configurations.
        // Does not necessary has to be IDP dependent, because as of the SAML2.0 core specification, the use
        // of this element is optional and by setting an explicit namespace, only IDPs who know about the extension
        // should be able to process it. Extensions that can't be processed by IDPs should be ignored (just like
        // the use of the extension for requesting attributes per request, defined by the SAML V2.0 Protocol Extension for Requesting Attributes per Request document).
        // But it is also possible that some IDP will throw an error, if they encounter an extension element,
        // that they can't process.
        // In order to be safe, the use of extensions should therefore also be IDP dependent.

        Extensions extensions = new ExtensionsBuilder().buildObject();
        extensions.getUnknownXMLObjects().add(createBundIdExtension());

        return extensions;
    }

    @NonNull
    private static XSAny createBundIdExtension() {
        // Version 2 demands that we request specific attributes.
        // Version 1 would include all by default, but will be removed in the future.
        final XSAny authenticationRequestBundIdRootContainer = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "AuthenticationRequest", EXTENSION_NAMESPACE_PREFIX);
        authenticationRequestBundIdRootContainer.getUnknownAttributes().put(new QName("Version"), new QName("2"));
        authenticationRequestBundIdRootContainer.getUnknownXMLObjects().add(createAuthnMethods());
        authenticationRequestBundIdRootContainer.getUnknownXMLObjects().add(createRequestedAttributes());

        return authenticationRequestBundIdRootContainer;
    }

    @NonNull
    private static XSAny createRequestedAttributes() {
        final XSAny requestedAttributesRootContainer = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "RequestedAttributes", EXTENSION_NAMESPACE_PREFIX);
        requestedAttributesRootContainer.getUnknownXMLObjects().add(createBPK2RequestedAttribute());

        return requestedAttributesRootContainer;
    }

    @NonNull
    private static XSAny createBPK2RequestedAttribute() {
        final XSAny bPK2Attribute = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "RequestedAttribute", EXTENSION_NAMESPACE_PREFIX);
        bPK2Attribute.getUnknownAttributes().put(new QName("Name"), new QName("urn:oid:1.3.6.1.4.1.25484.494450.3"));
        bPK2Attribute.getUnknownAttributes().put(new QName("RequiredAttribute"), new QName("true"));

        return bPK2Attribute;
    }

    @NonNull
    private static XSAny createAuthnMethods() {
        final XSAny requestedAuthnMethodsRootContainer = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "AuthnMethods", EXTENSION_NAMESPACE_PREFIX);
        requestedAuthnMethodsRootContainer.getUnknownXMLObjects().addAll(List.of(createUsernamePasswordAuthEnabled(), createEIDAuthEnabled()));

        return requestedAuthnMethodsRootContainer;
    }

    @NonNull
    private static XSAny createUsernamePasswordAuthEnabled() {
        final XSAny authnUsernamePasswordEnabled = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "Enabled", EXTENSION_NAMESPACE_PREFIX);
        authnUsernamePasswordEnabled.setTextContent("true");

        final XSAny authnUsernamePassword = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "Benutzername", EXTENSION_NAMESPACE_PREFIX);
        authnUsernamePassword.getUnknownXMLObjects().add(authnUsernamePasswordEnabled);

        return authnUsernamePassword;
    }

    @NonNull
    private static XSAny createEIDAuthEnabled() {
        final XSAny authnEIDEnabled = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "Enabled", EXTENSION_NAMESPACE_PREFIX);
        authnEIDEnabled.setTextContent("true");

        final XSAny authnEID = new XSAnyBuilder().buildObject(EXTENSION_NAMESPACE, "eID", EXTENSION_NAMESPACE_PREFIX);
        authnEID.getUnknownXMLObjects().add(authnEIDEnabled);

        return authnEID;
    }*/


    /**
     * Returns a requested authn context which sets the minimum BundID authentication level.
     *
     * @return a requested authn context which sets the minimum BundID authentication level.
     */
    @NonNull
    public static RequestedAuthnContext createRequestedContext(@NonNull final StorkQaaLevel authLevel) {
        // Build saml2p:RequestedAuthnContext
        // All IDP will check for this element and try to fulfill the requested authentication method.
        // The configuration must therefore be IDP-dependent, otherwise some IDOs will not be able to authenticate a user.
        // Using a custom extension can prevent that, because the extension are only read by identity providers
        // that expect some kind of extension.

        final RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        final AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setURI(authLevel.toString());

        final List<AuthnContextClassRef> authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();
        authnContextClassRefs.add(authnContextClassRef);

        return requestedAuthnContext;
    }
}
