package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import lombok.RequiredArgsConstructor;
import org.jooq.DSLContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import static eu.companyx.cms.auth.dto.companyx_backend.tables.SamlServiceProviderInformation.SAML_SERVICE_PROVIDER_INFORMATION;

/**
 * {@link SamlServiceProviderInformationRepository} implementation which uses JOOQ to access the
 * SAML specific key pair in a database.
 */
@Repository
@ConditionalOnClass(DSLContext.class)
@Profile("default")
@RequiredArgsConstructor
public class JooqSamlServiceProviderInformation implements SamlServiceProviderInformationRepository {

    @NonNull
    private final DSLContext dsl;

    @Nullable
    @Override
    public CertificateAndPrivateKeyInPEMFormat getCertificateInformation() {
        return dsl.select(
                        SAML_SERVICE_PROVIDER_INFORMATION.PRIVATE_KEY,
                        SAML_SERVICE_PROVIDER_INFORMATION.X509CERTIFICATE)
                .from(SAML_SERVICE_PROVIDER_INFORMATION)
                .where(SAML_SERVICE_PROVIDER_INFORMATION.PRIVATE_KEY.isNotNull())
                .and(SAML_SERVICE_PROVIDER_INFORMATION.X509CERTIFICATE.isNotNull())
                .fetchOne(row -> {
                    final String privateKeyPem = row.get(SAML_SERVICE_PROVIDER_INFORMATION.PRIVATE_KEY);
                    final String certificatePem = row.get(SAML_SERVICE_PROVIDER_INFORMATION.X509CERTIFICATE);
                    if (privateKeyPem.isEmpty() || certificatePem.isEmpty()) {
                        return null;
                    }
                    return new CertificateAndPrivateKeyInPEMFormat(privateKeyPem, certificatePem);
                });
    }

    @Override
    public void saveCertificateInformation(@NonNull final CertificateAndPrivateKeyInPEMFormat certificateAndPrivateKeyInPEMFormat) {
        dsl.update(SAML_SERVICE_PROVIDER_INFORMATION)
                .set(SAML_SERVICE_PROVIDER_INFORMATION.PRIVATE_KEY, certificateAndPrivateKeyInPEMFormat.privateKey())
                .set(SAML_SERVICE_PROVIDER_INFORMATION.X509CERTIFICATE, certificateAndPrivateKeyInPEMFormat.x509Certificate())
                .execute();
    }
}
