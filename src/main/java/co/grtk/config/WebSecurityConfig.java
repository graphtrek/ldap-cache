package co.grtk.config;

import co.grtk.security.SimpleCacheUserAuthenticationProvider;
import co.grtk.security.SimpleLdapAuthenticationProvider;
import co.grtk.security.SimpleUserCache;
import co.grtk.security.SimpleCacheUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    @Bean
    @ConfigurationProperties(prefix = "application.authentication")
    public SecurityConfigurationProperties securityConfigurationProperties() {
        return new SecurityConfigurationProperties();
    }

    @Bean
    public SimpleUserCache userCache(SecurityConfigurationProperties props) {
        return new SimpleUserCache(props.getLdap().getUserCacheExpiryMs());
    }

    @Bean
    public SimpleCacheUserDetailsService userDetailsService(SimpleUserCache simpleUserCache,
                                                            PasswordEncoder passwordEncoder) {
        return new SimpleCacheUserDetailsService(simpleUserCache, passwordEncoder);
    }

    @Bean
    public SimpleCacheUserAuthenticationProvider simpleCacheAuthenticationProvider(
            SimpleCacheUserDetailsService simpleCacheUserDetailsService,
            PasswordEncoder passwordEncoder) {
        SimpleCacheUserAuthenticationProvider authenticationProvider =
                new SimpleCacheUserAuthenticationProvider(simpleCacheUserDetailsService, passwordEncoder);
        return authenticationProvider;
    }

    @Bean
    @ConditionalOnBean(SimpleLdapAuthenticationProvider.class)
    public ProviderManager providerManagerWithLDAP(
            SimpleCacheUserAuthenticationProvider simpleCacheUserAuthenticationProvider,
            SimpleLdapAuthenticationProvider simpleLdapAuthenticationProvider) {

        return new ProviderManager(
                simpleCacheUserAuthenticationProvider,
                simpleLdapAuthenticationProvider);

    }

    @Bean
    @ConditionalOnMissingBean(SimpleLdapAuthenticationProvider.class)
    public ProviderManager providerManager(
            SecurityConfigurationProperties props,
            SimpleUserCache userCache,
            SimpleCacheUserAuthenticationProvider simpleCacheUserAuthenticationProvider) {

        if(!props.getLdap().isEnabled()) {
            userCache.putTechUserInCache(User.withUsername(props.getDevTechUser().getUsername())
                    .password(props.getDevTechUser().getPasswordHash())
                    .authorities("USER")
                    .build());

        }
        return new ProviderManager(
                simpleCacheUserAuthenticationProvider);

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            ProviderManager providerManager) throws Exception {

        http.authenticationManager(providerManager);
        http
                .csrf().disable()
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .httpBasic()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.headers().frameOptions().sameOrigin();
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers(
                "/actuator/**", "/images/**", "/js/**", "/webjars/**"
        );
    }
}