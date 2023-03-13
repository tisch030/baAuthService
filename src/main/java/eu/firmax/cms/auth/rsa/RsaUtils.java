package eu.firmax.cms.auth.rsa;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.OffsetDateTime;
import java.time.Period;
import java.util.Date;

/**
 * Provides utility helper functions to generate {@link X509Certificate}s, {@link RSAPrivateKey}s,
 * {@link CertificateAndPrivateKeyInPEMFormat}s and {@link CertificateAndPrivateKey}s,
 * or to transform them into the PEM format and vice versa.
 */
public class RsaUtils {

    /**
     * Transforms the {@link X509Certificate} and {@link RSAPrivateKey} inside the given {@link CertificateAndPrivateKey}
     * into the PEM format and wraps them inside the {@link CertificateAndPrivateKeyInPEMFormat}.
     *
     * @param certificateAndPrivateKey The container which contains the to be transformed {@link X509Certificate} and {@link RSAPrivateKey}.
     * @return a {@link CertificateAndPrivateKeyInPEMFormat} which contains the same {@link X509Certificate} and {@link RSAPrivateKey}
     * from the given {@link CertificateAndPrivateKey}, but in a PEM format.
     */
    @NonNull
    public static CertificateAndPrivateKeyInPEMFormat transformToPEM(@NonNull final CertificateAndPrivateKey certificateAndPrivateKey) {
        final String certificateInPemFormat = transformCertificateOrPrivateKeyIntoPEMFormat(certificateAndPrivateKey.x509Certificate());
        final String privateKeyInPemFormat = transformCertificateOrPrivateKeyIntoPEMFormat(certificateAndPrivateKey.privateKey());
        return new CertificateAndPrivateKeyInPEMFormat(privateKeyInPemFormat, certificateInPemFormat);
    }

    /**
     * Transforms the {@link X509Certificate} and {@link RSAPrivateKey} inside the given {@link CertificateAndPrivateKeyInPEMFormat}
     * from their PEM format into the actual java representation and wraps them inside the {@link CertificateAndPrivateKey}.
     *
     * @param certificateAndPrivateKey The container which contains the to be transformed {@link X509Certificate} and {@link RSAPrivateKey} in PEM format.
     * @return a {@link CertificateAndPrivateKey} which contains the same {@link X509Certificate} and {@link RSAPrivateKey}
     * from the given {@link CertificateAndPrivateKey}, but in the corresponding java representation.
     */
    @NonNull
    public static CertificateAndPrivateKey transformFromPEM(@NonNull final CertificateAndPrivateKeyInPEMFormat certificateAndPrivateKey) {
        final RSAPrivateKey rsaPrivateKey = transformPemPrivateKeyToRSAPrivateKey(certificateAndPrivateKey.privateKey());
        final X509Certificate x509Certificate = transformPemCertificateToX509Certificate(certificateAndPrivateKey.x509Certificate());
        return new CertificateAndPrivateKey(rsaPrivateKey, x509Certificate);
    }

    /**
     * Generates a {@link CertificateAndPrivateKey} which contains a {@link X509Certificate} and its corresponding {@link RSAPrivateKey}.
     * Uses {@link BouncyCastleProvider} as the security {@link Provider}.
     *
     * @param certificateValidityDuration      The duration for which the new {@link X509Certificate} should be valid for.
     * @param certificatePrivateKeyKeySize     The RSA key size which is used to generate the {@link RSAPrivateKey}.
     * @param certificateX509DistinguishedName The string representation of an X.500 distinguished name.
     * @param certificateSignatureAlgorithm    The algorithm which should be used to create the {@link X509Certificate}'s signature.
     * @return a {@link CertificateAndPrivateKey} which contains the generated {@link X509Certificate} and {@link RSAPrivateKey}.
     */
    @NonNull
    public static CertificateAndPrivateKey generateNewKeyPair(@NonNull final Period certificateValidityDuration,
                                                              final int certificatePrivateKeyKeySize,
                                                              @NonNull final String certificateX509DistinguishedName,
                                                              @NonNull final String certificateSignatureAlgorithm,
                                                              @NonNull final OffsetDateTime startDate) {

        // Add BouncyCastle as provider
        final Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        // Create certificate validity
        final Date certificateValidityStartDate = Date.from(startDate.toInstant());
        final Date certificateValidityEndDate = Date.from(startDate.plus(certificateValidityDuration).toInstant());

        try {
            // Generate public/private RSA key pair
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(certificatePrivateKeyKeySize, new SecureRandom());
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Generate X509 certificate
            final X500Principal dnName = new X500Principal(certificateX509DistinguishedName);
            final BigInteger certSerialNumber = new BigInteger(Long.toString(startDate.toInstant().getEpochSecond()));

            final ContentSigner contentSigner = new JcaContentSignerBuilder(certificateSignatureAlgorithm).build(keyPair.getPrivate());
            final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, certificateValidityStartDate, certificateValidityEndDate, dnName, keyPair.getPublic());
            final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));

            return new CertificateAndPrivateKey((RSAPrivateKey) keyPair.getPrivate(), certificate);

        } catch (final NoSuchProviderException | NoSuchAlgorithmException | OperatorCreationException |
                       CertificateException noSuchAlgorithmException) {
            throw new UnsupportedOperationException(noSuchAlgorithmException);
        }
    }

    /**
     * Takes a {@link RSAPrivateKey} in PEM format and transforms it into an actual {@link RSAPrivateKey}.
     *
     * @param privateKeyInPEM The {@link RSAPrivateKey} in PEM format.
     * @return an actual {@link RSAPrivateKey} which is based on the given private key in PEM format.
     */
    @NonNull
    public static RSAPrivateKey transformPemPrivateKeyToRSAPrivateKey(@NonNull final String privateKeyInPEM) {
        try {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) new PEMParser(new StringReader(privateKeyInPEM)).readObject();
            final Provider bcProvider = new BouncyCastleProvider();
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(bcProvider);
            return (RSAPrivateKey) converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (final IOException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * Takes a {@link X509Certificate} in PEM format and transforms it into an actual {@link X509Certificate}.
     *
     * @param x509Certificate The {@link X509Certificate} in PEM format.
     * @return an actual {@link X509Certificate} which is based on the given certificate in PEM format.
     */
    @NonNull
    public static X509Certificate transformPemCertificateToX509Certificate(@NonNull final String x509Certificate) {
        try {
            final InputStream targetStream = new ByteArrayInputStream(x509Certificate.getBytes(StandardCharsets.UTF_8));
            return (X509Certificate) CertificateFactory
                    .getInstance("X509")
                    .generateCertificate(targetStream);
        } catch (final CertificateException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * Takes a {@link X509Certificate} or {@link RSAPrivateKey} and transforms it into the PEM format representation.
     *
     * @param certificateOrPrivateKey The {@link X509Certificate} or {@link RSAPrivateKey} object which should be
     *                                transformed to the PEM representation.
     * @return a {@link X509Certificate} or {@link RSAPrivateKey} represented in the PEM format.
     */
    @NonNull
    public static String transformCertificateOrPrivateKeyIntoPEMFormat(@NonNull final Object certificateOrPrivateKey) {
        try {
            final StringWriter writer = new StringWriter();
            final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(certificateOrPrivateKey);
            pemWriter.flush();
            pemWriter.close();
            writer.close();
            return writer.toString();
        } catch (final IOException e) {
            throw new UnsupportedOperationException(e);
        }
    }

}
