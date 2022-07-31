package hu.erste.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
public class SecurityConfigurationProperties implements Validator {

    private LdapProperty ldap;
    private DevTechUserProperty devTechUser;

    @Override
    public boolean supports(Class<?> aClass) {
        return SecurityConfigurationProperties.class.isAssignableFrom(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
        SecurityConfigurationProperties properties = (SecurityConfigurationProperties) o;
        if (!properties.getLdap().isEnabled() && properties.getDevTechUser() == null) {
            errors.rejectValue("devTechUser", "", "devTechUser setting must be added if the ldap is not enabled!");
        }
    }

    @Getter
    @Setter
    public static class LdapProperty {
        private String url;
        private String baseDN = "dc=erste,dc=hu";
        private String userDnPattern = "uid={0},ou=Technical_accounts,ou=EBH";
        private String groupSearchBase = "ou=ESL,ou=Groups,ou=EBH";
        private String authorizedGroup = "APP_ESL_WS_USER";
        private boolean enabled = true;
        private int userCacheExpiryMs = 600 * 1000;
    }

    @Getter
    @Setter
    public static class DevTechUserProperty {
        private String username;
        private String passwordHash;
    }

}
