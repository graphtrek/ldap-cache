package co.grtk.security;

import co.grtk.config.SecurityConfigurationProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
@Slf4j
@AllArgsConstructor
public class SimpleLdapAuthenticationProvider implements AuthenticationProvider
{
    private SecurityConfigurationProperties props;

    private LdapTemplate ldapTemplate;
    private SimpleCacheUserDetailsService simpleCacheUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Filter filter = new EqualsFilter("uid", authentication.getName());
        Boolean authenticate =
                ldapTemplate.authenticate(
                        LdapUtils.emptyLdapName(),
                        filter.encode(),
                        authentication.getCredentials().toString());
        if (authenticate) {
            UserDetails userDetails =
                    new User(
                            authentication.getName(),
                            authentication.getCredentials().toString(),
                            new ArrayList<>());
            Authentication auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            authentication.getCredentials().toString(),
                            new ArrayList<>());
            simpleCacheUserDetailsService.cacheUser(userDetails);
            return auth;
        } else {
            log.warn("Invalid LDAP login details");
            throw new BadCredentialsException("Invalid LDAP login details");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}