package co.grtk.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;

@Slf4j
@AllArgsConstructor
public class SimpleCacheUserAuthenticationProvider implements AuthenticationProvider {

    SimpleCacheUserDetailsService userDetailsService;
    PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String username =
                (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        if (ObjectUtils.isEmpty(username)) {
            throw new BadCredentialsException("Invalid login details");
        }

        try {
            userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException exception) {
            throw new BadCredentialsException("User not found in cache, lookup in LDAP");
        }

        return createSuccessfulAuthentication(authentication);
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