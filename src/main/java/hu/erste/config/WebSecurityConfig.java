package hu.erste.config;

import hu.erste.security.SimpleCacheUserAuthenticationProvider;
import hu.erste.security.SimpleCacheUserDetailsService;
import hu.erste.security.SimpleUserCache;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
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
    public SimpleCacheUserAuthenticationProvider authenticationProvider(
            SimpleCacheUserDetailsService simpleCacheUserDetailsService,
            PasswordEncoder passwordEncoder) {
        SimpleCacheUserAuthenticationProvider authenticationProvider =
                new SimpleCacheUserAuthenticationProvider(simpleCacheUserDetailsService, passwordEncoder);
        return authenticationProvider;
    }

    @Bean
    public ProviderManager providerManager(SimpleCacheUserAuthenticationProvider authenticationProvider) {
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        return providerManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager) throws Exception {

        http.authenticationManager(authenticationManager);
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