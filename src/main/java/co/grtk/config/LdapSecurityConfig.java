package co.grtk.config;

import co.grtk.security.SimpleLdapAuthenticationProvider;
import co.grtk.security.SimpleCacheUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
@ConditionalOnProperty(prefix = "application.authentication.ldap", value = "enabled", matchIfMissing = true)
public class LdapSecurityConfig {
    @Bean
    public LdapContextSource ldapContextSource(SecurityConfigurationProperties props) {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(props.getLdap().getUrl());
        contextSource.setAnonymousReadOnly(true);
        contextSource.setUserDn(props.getLdap().getUserDnPattern());
        contextSource.setBase(props.getLdap().getBaseDN());
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate(LdapContextSource ldapContextSource) {
        return new LdapTemplate(ldapContextSource);
    }

    @Bean
    public SimpleLdapAuthenticationProvider simpleLdapAuthenticationProvider(
            SecurityConfigurationProperties props,
            LdapTemplate ldapTemplate,
            SimpleCacheUserDetailsService simpleCacheUserDetailsService){

        return new SimpleLdapAuthenticationProvider(
                props,
                ldapTemplate,
                simpleCacheUserDetailsService);
    }
}
