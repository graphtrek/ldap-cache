package hu.erste.security;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;
@AllArgsConstructor
public class SimpleCacheUserAuthenticationProvider implements AuthenticationProvider {

    SimpleCacheUserDetailsService userDetailsService;
    PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String username =
                (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        if (ObjectUtils.isEmpty(username)) {
            throw new BadCredentialsException("invalid login details");
        }
        // get user details using Spring security user details service
        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException exception) {
            createUser(authentication);
            // throw new BadCredentialsException("invalid login details");
        }
        return createSuccessfulAuthentication(authentication);
    }

    private void createUser(Authentication authentication){
        UserDetails user =
                User
                        .withUsername(authentication.getPrincipal().toString())
                        .authorities(authentication.getAuthorities())
                        .password(passwordEncoder.encode(authentication.getCredentials().toString()))
                        .build();
        userDetailsService.cacheUser(user);
    }

    private Authentication createSuccessfulAuthentication(final Authentication authentication) {
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(
                        authentication.getPrincipal().toString(),
                        authentication.getCredentials(),
                        authentication.getAuthorities());
        token.setDetails(authentication.getDetails());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
