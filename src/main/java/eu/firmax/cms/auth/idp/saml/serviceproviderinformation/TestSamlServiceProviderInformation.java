package eu.firmax.cms.auth.idp.saml.serviceproviderinformation;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

/**
 * {@link SamlServiceProviderInformationRepository} implementation which uses a preconfigured
 * SAML certificate and private key pair.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Primary
@Profile("test")
public class TestSamlServiceProviderInformation implements SamlServiceProviderInformationRepository {

    // Don't forget to update KeyCloak if the privateKey or certificate changes.
    private String privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" +
            " MIIEowIBAAKCAQEAmUob+ahapEtdQ8sALbx5auMSNED/fPL8B/cXS5qpwF6O8/Md\n" +
            " KBIOjFmOhZoKTERZOpYbK+Fdwqx5nlIazDVlbAKWKI+o4TttTUm0+7biDnoVPUfM\n" +
            " kQ22IX55A6gD58JbBz2RhfsWmhP7NkCDXvMiHF7GZf8x6VlZTsxgDxzILIHxen2L\n" +
            " /zBS10Fd5YsPeqeI5kuohNVV/LN7fokheCjX/+EVZmAw8dBflq/KlYWAviDf0txj\n" +
            " EWK1wufFSwIjrnyKy78l6JxhM/1pvNObRlynkrLYIduoLPe8YK7DMS/C34X+4W+r\n" +
            " 6OL5fKXXYLagP4eg6Q1ACVrrt2kTLIv94Tk35QIDAQABAoIBAEaPVXdDJo4P3ttw\n" +
            " 2yEya5Vm9p80+CW014x3EbMMe20AWb8zPk2OmkHCi5c2A919bLFKHTHCqF0O9WCK\n" +
            " HKm5PnlMa4A6OJuMtlBoSDXBxiaxzYsKvMBcVmTuiZfERB/vV+VqUs0gehPsdKtR\n" +
            " YOdY9W+ntJ2IrZnjNffOnbz3G7FYXGKIT5bfdJ68rC/HACzDmn41Mbw2EOxmiQ7X\n" +
            " fSneG22hX5la3LFNNFoW3QpRSGJkMlnuHL2B3yEoglnFWcHlQiN3qE4COVp9YT2O\n" +
            " +Pet8uic9dEVapl4ra5zMqs3WYgq+/F5aTO/oVMGQZxruVfYXO/24kn9eJKkkABp\n" +
            " PAptNHUCgYEA04mGR8i9tN/mLJVNvYAIHyZdRwrIwPWvjzLJqCS7FSskPMEo2j9Q\n" +
            " mKAGH+iYdOUnZGUh+AuTjFynHpCXbnUcLfDCE7BLdkYLlE55g4xxnOYyQDkbPXkb\n" +
            " lQK3Z2abc8Sf7cbh158mQh2DcvVjeUNjFftWflwN9mNmNmlLUo6wahMCgYEAuYJe\n" +
            " hAbMRLmO2R9DwvcAQz/7AjEC0m3HLPlEVzVx8TOFQqoZqZIxhXlN6fjDcQWDW58l\n" +
            " s7nuC7Klvea+Auuz/AGGkJbYwGQf0Ewo3m5b0R/3GRniVqJIbTKyWUAevH6zA3Zy\n" +
            " adZNYMympIR3XUyx+3W7A7D8UZRcLneQKcJ0lScCgYAFaooDoIIq9WihT5lT9sk+\n" +
            " cu8EeKQ3PJMoKXa8VWRs4FPnMlLnc6OOpNpDSuNMaumdSnGaNkGq4FxvDeiyrVDx\n" +
            " ZC6z7lmgR57YR0IZOilWiRZUSqIF6unn4M/tV9U3G5u0rNjvemWyX6sT8HCBlFYf\n" +
            " I/ZM+fJpkpX1YrDJBlpB/QKBgQCaK/DlBMlK7HP9mnA0XhcHzOqNHbJctANuKxNS\n" +
            " 7wXtEYZUqw180hT5+qB4LNgw3AYZZSBuR73AVw5LzrJntv/0FkiBbfxhmFSgRktI\n" +
            " 4KrKGCjB4bMrkN9kcVeruRBSU3HvFMdtkj7ojeyImdah4ZWhiGyOWs639fbOX2ue\n" +
            " aQ9+zQKBgAPvyAU0vKQ/cWyQbUdUrxkkFbWbdSAyps7NG2eB0dDRXqLw5auW5oqk\n" +
            " xxF4S+rCDSN50yWHwIredH74lWdOKBOKMvHQq/5XB9jRVa9F3a1ZRnvoXACNZar2\n" +
            " NQDZD7j1girEDdn8wmAZogt7iA5BEcHfdfQE2J6/KdQfl6C25xfT\n" +
            " -----END RSA PRIVATE KEY-----\n";
    private String certificatePem = "-----BEGIN CERTIFICATE-----\n" +
            " MIICpjCCAY6gAwIBAgIEYvNtkTANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwpj\n" +
            " YW1wdXNjb3JlMB4XDTIyMDgxMDA4MzQyNVoXDTI3MDgxMDA4MzQyNVowFTETMBEG\n" +
            " A1UEAxMKY2FtcHVzY29yZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            " AJlKG/moWqRLXUPLAC28eWrjEjRA/3zy/Af3F0uaqcBejvPzHSgSDoxZjoWaCkxE\n" +
            " WTqWGyvhXcKseZ5SGsw1ZWwCliiPqOE7bU1JtPu24g56FT1HzJENtiF+eQOoA+fC\n" +
            " Wwc9kYX7FpoT+zZAg17zIhxexmX/MelZWU7MYA8cyCyB8Xp9i/8wUtdBXeWLD3qn\n" +
            " iOZLqITVVfyze36JIXgo1//hFWZgMPHQX5avypWFgL4g39LcYxFitcLnxUsCI658\n" +
            " isu/JeicYTP9abzTm0Zcp5Ky2CHbqCz3vGCuwzEvwt+F/uFvq+ji+Xyl12C2oD+H\n" +
            " oOkNQAla67dpEyyL/eE5N+UCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAEZhfwY/g\n" +
            " OIm/jSgnKFyPQ94zxigNCNiiAeTosclKpJNar/xEQydvNVeqPTnwAF14lYkpqr3v\n" +
            " EyrmADt6FN7K43YLoe9TWL7gv0096sXSm8AXfVVQFhQu1i+VwR00UP7quzsmcxlf\n" +
            " kBjppZT/BZ5hX0V4RuCUxHn49UcYagfKUIQBuDTTwAUxBVd14Btx6fInOOD8ruXj\n" +
            " 0CWRzXK7saddN7w4KasVlI+tPaSBKi2HsiMqerjYaJKnbwIHmVO7/GKoNYqnw6u4\n" +
            " BU/Og0YuWSVnyqTdwULyvvB7x9F0FCc77Z0Dzdmom+oYUTVIEJN/FCtnFc7AJ0/K\n" +
            " HmaIhvtJ0jJRFw==\n" +
            " -----END CERTIFICATE-----\n";

    @Nullable
    @Override
    public CertificateAndPrivateKeyInPEMFormat getCertificateInformation() {
        return new CertificateAndPrivateKeyInPEMFormat(this.privateKeyPem, this.certificatePem);
    }

    @Override
    public void saveCertificateInformation(@NonNull final CertificateAndPrivateKeyInPEMFormat certificateAndPrivateKeyInPEMFormat) {
        this.privateKeyPem = certificateAndPrivateKeyInPEMFormat.privateKey();
        this.certificatePem = certificateAndPrivateKeyInPEMFormat.x509Certificate();
    }
}
