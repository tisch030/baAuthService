package eu.firmax.cms.auth.idp.saml.bundid;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * STORK - Secure Identity Across Borders Linked (EU project).
 * Used to limit the BundID authentication methods.
 * The selected level is treated as a lower boundary, so higher levels are also implicitly allowed.
 *
 * @see <a href="https://joinup.ec.europa.eu/collection/secure-identity-across-borders-linked-stork/document/eu-stork-project-deliverable-quality-authenticator-scheme">STORK Website</a>
 * @see <a href="https://joinup.ec.europa.eu/sites/default/files/document/2014-12/STORK%20Deliverable%20D2.3%20-%20Quality%20authenticator%20scheme.pdf">STORK Document</a>
 */
@RequiredArgsConstructor
public enum StorkQaaLevel {

    /**
     * The lowest value in the context of BundID. Allows i.a. username and password authentication.
     */
    LEVEL1("STORK-QAA-Level-1"),

    /**
     * Does not have an explicit authentication method assigned and therefore currently the same as {@link #LEVEL1}.
     */
    LEVEL2("STORK-QAA-Level-2"),

    /**
     * Restricts authentication i.a. to using an "Elster" certificate or "better".
     */
    LEVEL3("STORK-QAA-Level-3"),

    /**
     * The highest security level. Restrict authentication to identity card only.
     */
    LEVEL4("STORK-QAA-Level-4");

    private final String level;

    @Override
    @NonNull
    public String toString() {
        return level;
    }
}
