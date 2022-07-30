package hu.erste.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Simple {@link UserDetailsService} implementation with user cache
 */
@Slf4j
@AllArgsConstructor
@Getter
public class SimpleCacheUserDetailsService implements UserDetailsService {

    private SimpleUserCache userCache;
    private PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails user = userCache.getUserFromCache(username);
        if (user == null) {
            throw new UsernameNotFoundException(username + " not found in cache!");
        }
        log.info("{} user details loaded from cache!", username);
        return User.withUserDetails(user).build();
    }


    protected void cacheUser(UserDetails user) {
        log.info("{} successfully authenticated, put in cache", user.getUsername());
        userCache.putUserInCache(User.withUsername(user.getUsername())
                .authorities(user.getAuthorities())
                .password(passwordEncoder.encode(user.getPassword())).build());
    }
}
