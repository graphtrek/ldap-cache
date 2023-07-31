package co.grtk.config;

import co.grtk.security.SimpleCacheUserAuthenticationProvider;
import co.grtk.security.SimpleCacheUserDetailsService;
import co.grtk.security.SimpleLdapAuthenticationProvider;
import co.grtk.security.SimpleUserCache;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Bean
    @ConfigurationProperties(prefix = "application.authentication")
    public SecurityConfigurationProperties securityConfigurationProperties() {
        return new SecurityConfigurationProperties();
    }

    @Bean
    public SimpleUserCache simpleEserCache(SecurityConfigurationProperties props) {
        return new SimpleUserCache(props.getLdap().getUserCacheExpiryMs());
    }

    @Bean
    public SimpleCacheUserDetailsService userDetailsService(SimpleUserCache simpleUserCache,
                                                            PasswordEncoder passwordEncoder) {
        return new SimpleCacheUserDetailsService(simpleUserCache, passwordEncoder);
    }

    @Bean
    public SimpleCacheUserAuthenticationProvider simpleCacheUserAuthenticationProvider(
            SimpleCacheUserDetailsService simpleCacheUserDetailsService,
            PasswordEncoder passwordEncoder) {
        return new SimpleCacheUserAuthenticationProvider(simpleCacheUserDetailsService, passwordEncoder);
    }

    @Bean
    @ConditionalOnBean(SimpleLdapAuthenticationProvider.class)
    public AuthenticationManager authenticationManagerWithLDAP(
            SimpleCacheUserAuthenticationProvider simpleCacheUserAuthenticationProvider,
            SimpleLdapAuthenticationProvider simpleLdapAuthenticationProvider) {

        return new ProviderManager(
                simpleCacheUserAuthenticationProvider,
                simpleLdapAuthenticationProvider);

    }

    @Bean
    @ConditionalOnMissingBean(SimpleLdapAuthenticationProvider.class)
    public AuthenticationManager authenticationManager(
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
            AuthenticationManager authenticationManager) throws Exception {

        http.authenticationManager(authenticationManager);
        http.csrf(c -> c.disable())
                .authorizeHttpRequests( auth -> auth
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/actuator/**")).permitAll()
                        .anyRequest().authenticated()
                )
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}