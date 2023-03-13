package eu.firmax.cms.auth.jwk;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKey;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import eu.firmax.cms.auth.rsa.RsaUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service that handles the creation of {@link JWKSet}s.
 */
@Component
@RequiredArgsConstructor
public class JwksService {

    @NonNull
    private final JwtKeyStoreRepository jwtKeyStoreRepository;

    @NonNull
    private final JwkProperties jwkProperties;

    /**
     * Returns a {@link JWKSet} with either existing or newly created {@link JWK}'s based of
     * loaded {@link StoredJwk}s.
     * <p>
     * Creates also a new {@link JWK}, if the {@link StoredJwk#notAfter()} of an existing {@link StoredJwk}
     * will be reached within a month and thus no valid/applicable {@link StoredJwk} for the creation
     * of a {@link JWK} would be existing at that time.
     * This would lead to a downtime, till a new {@link JWK} gets created.
     * Depending on the settings/timings of the cache, this may take a while, resulting in a long downtime.
     * The created {@link JWK} in this case would start right after the {@link StoredJwk} with the highest
     * {@link StoredJwk#notAfter()} value, resulting in a minimal downtime.
     *
     * @return a {@link JWKSet} with either existing or newly created {@link JWK}s.
     */
    @NonNull
    public JWKSet loadOrCreateJwkSet() {
        final List<StoredJwk> storedJwks = jwtKeyStoreRepository.getValidJwks();
        if (storedJwks.isEmpty()) {
            // We need at least one jwk, create it.
            final StoredJwk newJwk = createNewJwk(OffsetDateTime.now(Clock.systemUTC()));
            storedJwks.add(newJwk);
        }

        // Check if we need to generate a new cert for the near future.
        storedJwks.stream()
                .map(StoredJwk::notAfter)
                .max(Comparator.naturalOrder())
                .filter(lastNotAfter -> lastNotAfter.isBefore(LocalDateTime.now().plus(1, ChronoUnit.MONTHS)))
                .ifPresent(lastNotAfter -> {
                    final StoredJwk newJwk = createNewJwk(OffsetDateTime.from(lastNotAfter.plus(1, ChronoUnit.SECONDS)));
                    storedJwks.add(newJwk);
                });

        // We ensured that at least one jwk exists in the list.
        final List<JWK> jwks = storedJwks.stream()
                .map(this::parseKey)
                .collect(Collectors.toList());
        return new JWKSet(jwks);
    }

    /**
     * Creates a new {@link StoredJwk} where the validity of the information begins on the given start date.
     *
     * @param startDate The date from which on the {@link StoredJwk} information should be considered valid.
     * @return a newly created {@link StoredJwk}.
     */
    @NonNull
    private StoredJwk createNewJwk(@NonNull final OffsetDateTime startDate) {
        final CertificateAndPrivateKey key = RsaUtils.generateNewKeyPair(
                jwkProperties.getCertificateValidityDuration(),
                jwkProperties.getCertificatePrivateKeyKeySize(),
                jwkProperties.getCertificateX509DistinguishedName(),
                jwkProperties.getCertificateSignatureAlgorithm(),
                startDate);
        final CertificateAndPrivateKeyInPEMFormat pem = RsaUtils.transformToPEM(key);
        final StoredJwk storedJwk = new StoredJwk(UUID.randomUUID().toString(), pem,
                key.x509Certificate().getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime(),
                key.x509Certificate().getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        jwtKeyStoreRepository.createJwk(storedJwk);
        return storedJwk;
    }

    /**
     * Creates a {@link JWK} based on the information of the given {@link StoredJwk}.
     *
     * @param jwk The {@link StoredJwk} which should be used to create the {@link JWK}.
     * @return a {@link JWK} based on the information of the given {@link StoredJwk}.
     */
    @NonNull
    private JWK parseKey(@NonNull final StoredJwk jwk) {
        final CertificateAndPrivateKey certificateAndPrivateKey = RsaUtils.transformFromPEM(jwk.key());
        return new RSAKey.Builder((RSAPublicKey) certificateAndPrivateKey.x509Certificate().getPublicKey())
                .privateKey(certificateAndPrivateKey.privateKey())
                .keyID(jwk.keyId())
                .build();
    }
}
