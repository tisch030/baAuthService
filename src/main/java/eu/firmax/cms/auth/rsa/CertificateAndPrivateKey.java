package eu.firmax.cms.auth.rsa;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

/**
 * Container for the information of a x509-Certificate and private key combination.
 *
 * @param privateKey      The private key of the corresponding public key inside the x509-Certificate.
 * @param x509Certificate The x509-Certificate containing the corresponding public key of the given private key.
 */
public record CertificateAndPrivateKey(@NonNull RSAPrivateKey privateKey,
                                       @NonNull X509Certificate x509Certificate) {
}
