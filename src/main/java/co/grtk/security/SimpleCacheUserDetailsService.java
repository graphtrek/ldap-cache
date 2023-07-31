package co.grtk.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Simple {@link org.springframework.security.core.userdetails.UserDetailsService} implementation with user cache
 */
@Slf4j
@AllArgsConstructor
@Getter
public class SimpleCacheUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private SimpleUserCache userCache;
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails user = userCache.getUserFromCache(username);
        if (user == null) {
            log.info("User not found in cache username:{}", username);
            throw new UsernameNotFoundException(username + " not found in cache!");
        }
        log.info("User found in cache username:{}", username);
        return User.withUserDetails(user).build();
    }

    protected void cacheUser(UserDetails user) {
        log.info("User successfully authenticated, put in cache username:{}", user.getUsername());
        userCache.putUserInCache(User.withUsername(user.getUsername())
                .authorities(user.getAuthorities())
                .password(passwordEncoder.encode(user.getPassword())).build());
    }
}
