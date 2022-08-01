package co.grtk.config;


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
        private String url = "ldap://localhost:8389";
        private String baseDN = "dc=springframework,dc=org";
        private String userDnPattern = "uid={0},ou=people";
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