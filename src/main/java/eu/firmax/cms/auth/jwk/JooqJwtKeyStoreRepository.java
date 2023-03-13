package eu.firmax.cms.auth.jwk;

import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.JwtKeyStore.JWT_KEY_STORE;

/**
 * {@link JwtKeyStoreRepository} implementation which uses JOOQ to access the JWT keys in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqJwtKeyStoreRepository implements JwtKeyStoreRepository {

    @NonNull
    private final DSLContext dsl;

    @Override
    @NonNull
    public List<StoredJwk> getValidJwks() {
        return dsl.select(
                        JWT_KEY_STORE.ID,
                        JWT_KEY_STORE.PRIVATE_KEY,
                        JWT_KEY_STORE.PUBLIC_KEY,
                        JWT_KEY_STORE.NOT_BEFORE,
                        JWT_KEY_STORE.NOT_AFTER)
                .from(JWT_KEY_STORE)
                .where(JWT_KEY_STORE.NOT_AFTER.greaterOrEqual(LocalDateTime.now()))
                .fetch(row -> {

                    final String privateKeyPem = row.get(JWT_KEY_STORE.PRIVATE_KEY);
                    final String certificatePem = row.get(JWT_KEY_STORE.PUBLIC_KEY);
                    final CertificateAndPrivateKeyInPEMFormat keyPair = new CertificateAndPrivateKeyInPEMFormat(privateKeyPem, certificatePem);

                    return new StoredJwk(row.get(JWT_KEY_STORE.ID),
                            keyPair,
                            row.get(JWT_KEY_STORE.NOT_BEFORE),
                            row.get(JWT_KEY_STORE.NOT_AFTER));
                });
    }

    @Override
    public void createJwk(@NonNull final StoredJwk jwks) {
        dsl.insertInto(JWT_KEY_STORE)
                .set(JWT_KEY_STORE.ID, jwks.keyId())
                .set(JWT_KEY_STORE.PRIVATE_KEY, jwks.key().privateKey())
                .set(JWT_KEY_STORE.PUBLIC_KEY, jwks.key().x509Certificate())
                .set(JWT_KEY_STORE.NOT_BEFORE, jwks.notBefore())
                .set(JWT_KEY_STORE.NOT_AFTER, jwks.notAfter())
                .execute();
    }
}
