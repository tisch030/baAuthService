package eu.firmax.cms.auth.idp.saml.logout;

import edu.umd.cs.findbugs.annotations.NonNull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.stereotype.Service;

/**
 * {@link Saml2LogoutRequestRepository} implementation which uses the {@link HttpSessionLogoutRequestRepository}
 * for the management of {@link Saml2LogoutRequest}s.
 * Using the {@link HttpSessionLogoutRequestRepository} for the tests is ok, because we use {@link TestSessionRepository}
 * that manages the sessions in memory and therefore the {@link Saml2LogoutRequest}s won't get serialized.
 * Needed for tests to avoid a redis dependency.
 */
@Service
@Primary
@Profile("test")
@RequiredArgsConstructor
public class TestSamlLogoutRequestRepository implements Saml2LogoutRequestRepository {

    @NonNull
    private final Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();


    @Override
    public Saml2LogoutRequest loadLogoutRequest(final HttpServletRequest request) {
        return logoutRequestRepository.loadLogoutRequest(request);
    }

    @Override
    public void saveLogoutRequest(final Saml2LogoutRequest logoutRequest,
                                  final HttpServletRequest request,
                                  final HttpServletResponse response) {
        logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);

    }

    @Override
    public Saml2LogoutRequest removeLogoutRequest(final HttpServletRequest request,
                                                  final HttpServletResponse response) {
        return logoutRequestRepository.removeLogoutRequest(request, response);
    }
}
