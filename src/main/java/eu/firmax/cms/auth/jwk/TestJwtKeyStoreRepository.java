package eu.firmax.cms.auth.jwk;


import edu.umd.cs.findbugs.annotations.NonNull;
import eu.firmax.cms.auth.rsa.CertificateAndPrivateKeyInPEMFormat;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * {@link JwtKeyStoreRepository} implementation which uses preconfigured JWKs information.
 * Needed for tests to avoid a database dependency.
 */
@Repository
@Primary
@Profile("test")
public class TestJwtKeyStoreRepository implements JwtKeyStoreRepository {

    private static final String JWK_ID = "TEST_JWKS_ID_1";
    private static final String PRIVATE_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAonsjKK0EbefKjG0SuK9+xi3WugjnEO/e7Q4Kp9qqybQ9P7sr\n" +
            "hPkYfh4xGbLUFkmQ3TJfUbaZuPjCTEfwtyMO/14WjsaIg3PeQrhcV9A27DDBeRyZ\n" +
            "TSRBD2WdO29SXF4txqg/9LbM6vM6XhPu023eH9a9uT+XibVvKgZ5K11VC3ta/TZC\n" +
            "jiMkcAi5mnwVE08JThMf/ZTHMq1JfzkvY20GbjeaER//hAPXfaE1uqrzRPycVO00\n" +
            "JiYhTZoLzCYB85IidApXwVhvvX6b5EDp4lGbALHzYtRjl/HYcwNhNRtn9tlByq9W\n" +
            "5Xa0LYmvsCYDMh8Fh2+e/TQzDg5X2tfzu7DJUwIDAQABAoIBADz0mkeXxSogQ9Yz\n" +
            "00qzGAnsR3rKfTlW7Bid5HR9bgY21qWSp+x+cOhblksQUk28MpsxWx4yNXB17pqk\n" +
            "gJOMFQPLvgW5SJycOv1n4cjV5cztK6AukPqmR7wpgHe8NzdM47p8A2Zgr/bS4gpK\n" +
            "SxZJyQPD0bBuQYEZrocjH5EbthyUhME248XmBYfr9dUnRneYXt5Hh747lkbutgpM\n" +
            "54AC/ygwKhaw1kN0ABQIqfc8rHueTF+wgHEgPYNQIfWVAhZ1yGDQ6M9qdETdAq6B\n" +
            "oVGxaFhCRfe94arrjyn5qFX5ZPVZTA4d6Jy3D40be/9W230LRIL5RvGKOlf6Z0P1\n" +
            "Ylh0qKECgYEA2YoL85NRmFR7TutTQWdGpnsTIenbqNvGJbfl6pfmRIdg4XFZBbzo\n" +
            "iaCwFQuaZD7+FRCg2wHhBcIwolqGWOcgVFpDCQ+787QpS4tKKxAK69N2RkvaQzKg\n" +
            "oUTb5avHXukXKI5T9XApIu9oTcg14Oh1m2SQd7B0S+MPEyBJjvgXRfMCgYEAvzUf\n" +
            "YDV/rUAUHJtlXg/oj7xavWzCf/Qsouq44OFYYTDsbYMLpmN0KroG96EnCqUHDQWz\n" +
            "htbuaf1bOkTgpCe7KoITIhBKwdDavvd8k1DW501RL3dX/Qm2oTJ3fJ+GU7ubvFq+\n" +
            "0fiqvQI6gYudSSRXevMOR7MG7QsjbXUi67VEZyECgYAsJ17ho4cuOgeFLzKI1eN7\n" +
            "KwPpIERbc7A2O6tJAGfWhPvfBlihV4SDWsAipWZC7p43vFZJ3YnE13NzoJggN1lS\n" +
            "hbeRgUYO4wR2tuDo+Kqezx70ibTVatM7qHRRm5ot43W1352e9ZMD6j/rebWl3sjw\n" +
            "L2s7P+96761Bno4PnL9sjQKBgQC7/Uy12KOJAMFFRvsouddaykMkjjPEfZsNKl1O\n" +
            "q/+qvuEU4oynsIxcHb4P5R9vdcUy5nIVlmedSX1SEroSawW3y19oVEBLwj3vF4Ah\n" +
            "jo9bpka1tk6J9+zZG7cije0RkhiR3V5TLnsfjXtcNpoTeWmQ9jsJ/1hF4neYfFwz\n" +
            "BmsUQQKBgQCIT1n0QhOfz4zYP/OmIVXHpMIquNqyel3o+Ak8DTbiF9J8dOF9mVM8\n" +
            "1AKoT7WEHM2j20PzNmjSHPsrad9H5DMujn15cW4xVgCFhRcx2npajEGzAjBtiGUm\n" +
            "48FZgg+WxzkDrfBM9Vwr1OTDuN8kd7GH2WuutzXDVLLqBlWpvWD3tg==\n" +
            "-----END RSA PRIVATE KEY-----\n";
    public static final String PUBLIC_KEY_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIICpjCCAY6gAwIBAgIEYz6cMDANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwpj\n" +
            "YW1wdXNjb3JlMB4XDTIyMTAwNjA5MTMyMFoXDTI3MTAwNjA5MTMyMFowFTETMBEG\n" +
            "A1UEAxMKY2FtcHVzY29yZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AKJ7IyitBG3nyoxtErivfsYt1roI5xDv3u0OCqfaqsm0PT+7K4T5GH4eMRmy1BZJ\n" +
            "kN0yX1G2mbj4wkxH8LcjDv9eFo7GiINz3kK4XFfQNuwwwXkcmU0kQQ9lnTtvUlxe\n" +
            "LcaoP/S2zOrzOl4T7tNt3h/Wvbk/l4m1byoGeStdVQt7Wv02Qo4jJHAIuZp8FRNP\n" +
            "CU4TH/2UxzKtSX85L2NtBm43mhEf/4QD132hNbqq80T8nFTtNCYmIU2aC8wmAfOS\n" +
            "InQKV8FYb71+m+RA6eJRmwCx82LUY5fx2HMDYTUbZ/bZQcqvVuV2tC2Jr7AmAzIf\n" +
            "BYdvnv00Mw4OV9rX87uwyVMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAef4kEb1I\n" +
            "75Ar3IXVmNk6pxoAONvt++j6bUV/Ifyh4q9wR9V+blnopkyBsOf3nIOVbpbO61MF\n" +
            "j2tlje+qhuIS69PhHjiJBIA55QmcSyUCxAIJVGTG7VqhIRRn50wzI2eSlGlXsBcV\n" +
            "FQSy06ziy0sWwYMnOdnlsEFcE+M31EouhJ8/q759vR1iLHB2fIoB/2ubeo1BSHav\n" +
            "l2oJ+5f9lnuHZrcdwAhWUjvqrYmpr+k2cCf3FvL+uUqdOb/5OnwzN61bjvfq+zao\n" +
            "nLReG3LjxaDEyoLgUqIljVssPXZiM5BX66N17uOrXAX0+S9mBlsZeFcrGaYyJyjo\n" +
            "S3Aj+4mXyIjLMA==\n" +
            "-----END CERTIFICATE-----\n";
    private static final LocalDateTime NOT_BEFORE = LocalDateTime.of(2022, 10, 6, 11, 30, 20, 15);
    private static final LocalDateTime NOT_AFTER = LocalDateTime.of(2027, 10, 6, 11, 30, 20, 15);
    private static final CertificateAndPrivateKeyInPEMFormat KEY_PAIR = new CertificateAndPrivateKeyInPEMFormat(PRIVATE_KEY_PEM, PUBLIC_KEY_PEM);
    private static final StoredJwk TEST_JWK = new StoredJwk(JWK_ID, KEY_PAIR, NOT_BEFORE, NOT_AFTER);
    private final Set<StoredJwk> storedJwks = new HashSet<>();

    @Override
    @NonNull
    public List<StoredJwk> getValidJwks() {
        // Ensure that the default test jwk is present. Since this is a set, duplicates will be ignored.
        storedJwks.add(TEST_JWK);

        return storedJwks.stream().toList();
    }

    @Override
    public void createJwk(@NonNull final StoredJwk jwks) {
        storedJwks.add(jwks);
    }
}
