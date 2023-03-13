package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.jwk.JWK;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;

import java.time.LocalDateTime;

/**
 * Container which holds information for a {@link JWK}.
 *
 * @param keyId     The id of the key. Correlates to {@link JWK#getKeyID()}.
 * @param key       Container which holds the public key and private key information in PEM format.
 * @param notBefore The date from which on the key information should be used.
 * @param notAfter  The date from which on the key information should not be used anymore.
 */
public record StoredJwk(@NonNull String keyId,
                        @NonNull CertificateAndPrivateKeyInPEMFormat key,
                        @NonNull LocalDateTime notBefore,
                        @NonNull LocalDateTime notAfter) {
}
