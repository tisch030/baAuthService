package eu.firmax.cms.auth.rsa;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Container for a x509-Certificate and private key combination, which are in the PEM format.
 *
 * @param privateKey      The private key of the corresponding public key inside the x509-Certificate.
 * @param x509Certificate The x509-Certificate containing the corresponding public key of the given private key.
 */
public record CertificateAndPrivateKeyInPEMFormat(@NonNull String privateKey,
                                                  @NonNull String x509Certificate) {
}
