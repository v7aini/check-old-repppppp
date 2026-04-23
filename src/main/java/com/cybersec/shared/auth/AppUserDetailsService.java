package com.cybersec.shared.auth;
import com.cybersec.shared.model.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class AppUserDetailsService implements UserDetailsService {
    private final UserRepository userRepo;

    @Autowired
    public AppUserDetailsService(UserRepository userRepo) { this.userRepo = userRepo; }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser u = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new User(u.getUsername(), u.getPassword(), u.isEnabled(), true, true, true,
                List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole())));
    }
}
