package eu.firmax.cms.auth.local.database;

import edu.umd.cs.findbugs.annotations.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Implementation of {@link UserDetailsService} that loads the user details from a database.
 */
@Service
@RequiredArgsConstructor
public class DatabaseUserDetailsService implements UserDetailsService {

    @NonNull
    private final UserDetailsRepository userDetailsRepository;

    @Override
    @NonNull
    public UserDetails loadUserByUsername(@NonNull final String username) throws UsernameNotFoundException {
        return userDetailsRepository.lookupUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found in the database"));
    }
}
